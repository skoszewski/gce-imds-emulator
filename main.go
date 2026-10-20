// Command imds-emulator serves the access tokens of the Application Default
// Credentials on the Compute Engine metadata server (IMDS) endpoints.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // Time zone data used when the system has none.

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	_ "golang.org/x/crypto/x509roots/fallback" // Root certificates used when the system has none.
)

const (
	defaultScope   = "https://www.googleapis.com/auth/cloud-platform"
	root           = "/computeMetadata/v1/"
	accounts       = "instance/service-accounts/"
	defaultAccount = accounts + "default/"

	// shutdownGrace is shorter than the stop grace period of the container.
	shutdownGrace = 20 * time.Second

	// maxProviders bounds the token providers kept for distinct scope sets.
	maxProviders = 16
)

// tokenFunc returns an access token for the scopes.
type tokenFunc func(ctx context.Context, scopes []string) (*auth.Token, error)

// serviceAccount is the metadata of a service account.
type serviceAccount struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

// metadataServer answers the IMDS requests of the Google client libraries.
type metadataServer struct {
	email         string
	projectID     string
	projectNumber string
	hostname      string
	token         tokenFunc
	now           func() time.Time
}

// ServeHTTP answers a request and logs its method, path and status.
func (s *metadataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Metadata-Flavor", "Google")
	w.Header().Set("Server", "Metadata Server for VM")
	status := s.handle(w, r)
	log.Printf("%s %s %d", r.Method, r.URL.EscapedPath(), status)
}

// handle writes the response of a request and returns its status.
func (s *metadataServer) handle(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return text(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}

	// The real IMDS rejects requests without the flavor header and proxied requests.
	if r.Header.Get("Metadata-Flavor") != "Google" || r.Header.Get("X-Forwarded-For") != "" {
		return text(w, http.StatusForbidden, "Forbidden")
	}

	if r.URL.Path == "/" || r.URL.Path == root {
		return text(w, http.StatusOK, "")
	}
	path, found := strings.CutPrefix(r.URL.Path, root)
	if !found {
		return text(w, http.StatusNotFound, "Not Found")
	}

	// Both "default" and the email address name the service account.
	for _, alias := range []string{"default", s.email} {
		if rest, found := strings.CutPrefix(path, accounts+alias+"/"); found {
			path = defaultAccount + rest
			break
		}
	}

	query := r.URL.Query()
	recursive := query.Get("recursive") == "true"
	account := serviceAccount{Aliases: []string{"default"}, Email: s.email, Scopes: []string{defaultScope}}

	switch {
	case path == defaultAccount+"token":
		token, err := s.token(r.Context(), parseScopes(query.Get("scopes")))
		if err != nil {
			log.Printf("token error: %q", err)
			return text(w, http.StatusInternalServerError, "Internal Server Error")
		}
		expiresIn := 3600
		if !token.Expiry.IsZero() {
			expiresIn = max(int(token.Expiry.Sub(s.now()).Seconds()), 0)
		}
		return jsonBody(w, map[string]any{
			"access_token": token.Value,
			"expires_in":   expiresIn,
			"token_type":   cmp.Or(token.Type, "Bearer"),
		})
	case path == defaultAccount+"email":
		return text(w, http.StatusOK, s.email)
	case path == defaultAccount+"scopes":
		return text(w, http.StatusOK, defaultScope+"\n")
	case path == defaultAccount && recursive:
		return jsonBody(w, account)
	case path == defaultAccount:
		return text(w, http.StatusOK, "aliases\nemail\nscopes\ntoken\n")
	case path == accounts && recursive:
		return jsonBody(w, map[string]serviceAccount{"default": account, s.email: account})
	case path == accounts:
		return text(w, http.StatusOK, "default/\n"+s.email+"/\n")
	case path == "project/project-id" && s.projectID != "":
		return text(w, http.StatusOK, s.projectID)
	case path == "project/numeric-project-id" && s.projectNumber != "":
		return text(w, http.StatusOK, s.projectNumber)
	case path == "instance/hostname":
		return text(w, http.StatusOK, s.hostname)
	case path == "universe/universe-domain":
		return text(w, http.StatusOK, "googleapis.com")
	}
	return text(w, http.StatusNotFound, "Not Found")
}

// parseScopes returns the comma separated scopes of the query, or the default scope.
func parseScopes(value string) []string {
	scopes := slices.DeleteFunc(strings.Split(value, ","), func(scope string) bool { return scope == "" })
	if len(scopes) == 0 {
		return []string{defaultScope}
	}
	return scopes
}

// text writes a plain text response and returns its status.
func text(w http.ResponseWriter, status int, body string) int {
	w.Header().Set("Content-Type", "application/text")
	w.WriteHeader(status)
	if _, err := io.WriteString(w, body); err != nil {
		log.Printf("write error: %v", err)
	}
	return status
}

// jsonBody writes a JSON response with the status 200 and returns it.
func jsonBody(w http.ResponseWriter, value any) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write error: %v", err)
	}
	return http.StatusOK
}

// ping checks that the emulator at the address answers the metadata ping.
func ping(address string) error {
	request, err := http.NewRequest(http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Metadata-Flavor") != "Google" {
		return fmt.Errorf("unexpected response: %s", response.Status)
	}
	return nil
}

var impersonationURL = regexp.MustCompile(`/serviceAccounts/([^/:]+):generateAccessToken$`)

// serviceAccountEmail returns the service account of a credentials file, or an empty string.
func serviceAccountEmail(credentialsJSON []byte) string {
	var file struct {
		ClientEmail      string `json:"client_email"`
		ImpersonationURL string `json:"service_account_impersonation_url"`
	}
	if json.Unmarshal(credentialsJSON, &file) != nil {
		return ""
	}
	if match := impersonationURL.FindStringSubmatch(file.ImpersonationURL); match != nil {
		return match[1]
	}
	return file.ClientEmail
}

// providerCache keeps one token provider per set of scopes.
type providerCache struct {
	mu        sync.Mutex
	detect    func(scopes []string) (auth.TokenProvider, error)
	providers map[string]auth.TokenProvider
}

// get returns the token provider of the scopes, creating it on first use.
func (c *providerCache) get(scopes []string) (auth.TokenProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := strings.Join(scopes, ",")
	if provider, found := c.providers[key]; found {
		return provider, nil
	}
	provider, err := c.detect(scopes)
	if err != nil {
		return nil, err
	}
	if c.providers == nil {
		c.providers = map[string]auth.TokenProvider{}
	}
	// Drop all providers once the limit is reached, so the cache never grows unbounded.
	if len(c.providers) >= maxProviders {
		clear(c.providers)
	}
	c.providers[key] = provider
	return provider, nil
}

// token returns a token for the scopes, independent of their order.
func (c *providerCache) token(ctx context.Context, scopes []string) (*auth.Token, error) {
	sorted := slices.Sorted(slices.Values(scopes))
	provider, err := c.get(sorted)
	if err != nil {
		return nil, err
	}
	return provider.Token(ctx)
}

// serve serves the listener until the context is canceled, then stops the
// server, waiting up to the grace period for the requests in progress.
func serve(ctx context.Context, server *http.Server, listener net.Listener, grace time.Duration) error {
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(listener) }()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		server.Close()
		return err
	}
	<-failed
	return nil
}

func main() {
	check := flag.Bool("check", false, "check that the emulator answers and exit")
	flag.Parse()

	// IMDS_HOST empty binds all interfaces; the check then uses the loopback address.
	host, port := os.Getenv("IMDS_HOST"), cmp.Or(os.Getenv("IMDS_PORT"), "8080")
	if *check {
		if err := ping(net.JoinHostPort(cmp.Or(host, "127.0.0.1"), port)); err != nil {
			log.Fatalf("Check failed: %v", err)
		}
		return
	}

	// The first signal stops the server gracefully, the second one exits at once.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		log.Printf("Received %v, shutting down", <-signals)
		cancel()
		log.Printf("Received %v again, exiting", <-signals)
		os.Exit(1)
	}()

	detect := func(scopes []string) (auth.TokenProvider, error) {
		creds, err := credentials.DetectDefault(&credentials.DetectOptions{Scopes: scopes})
		if err != nil {
			return nil, err
		}
		return creds, nil
	}
	defaults, err := credentials.DetectDefault(&credentials.DetectOptions{Scopes: []string{defaultScope}})
	if err != nil {
		log.Fatalf("Cannot find the Application Default Credentials: %v", err)
	}

	email := cmp.Or(os.Getenv("SERVICE_ACCOUNT_EMAIL"), serviceAccountEmail(defaults.JSON()))
	if email == "" {
		log.Fatal("The service account email is unknown, set SERVICE_ACCOUNT_EMAIL")
	}
	projectID := os.Getenv("PROJECT_ID")
	if projectID == "" {
		projectID, _ = defaults.ProjectID(ctx)
	}
	hostname, _ := os.Hostname()

	// The credentials detected at startup serve the default scope.
	cache := &providerCache{detect: detect, providers: map[string]auth.TokenProvider{defaultScope: defaults}}
	server := &metadataServer{
		email:         email,
		projectID:     projectID,
		projectNumber: os.Getenv("PROJECT_NUMBER"),
		hostname:      cmp.Or(os.Getenv("IMDS_HOSTNAME"), hostname),
		token:         cache.token,
		now:           time.Now,
	}
	httpServer := &http.Server{
		Handler:           server,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatalf("Cannot listen: %v", err)
	}

	log.Printf("Serving tokens of %s for project %s on %s", email, cmp.Or(projectID, "-"), listener.Addr())
	if err := serve(ctx, httpServer, listener, shutdownGrace); err != nil {
		log.Fatalf("Server stopped: %v", err)
	}
	log.Print("Stopped")
}
