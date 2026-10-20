package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

const (
	testEmail = "sa-test@dom-lab.iam.gserviceaccount.com"
	mainEnv   = "IMDS_EMULATOR_RUN_MAIN"
)

var testNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	// The signal tests run the test binary as the emulator.
	if os.Getenv(mainEnv) == "1" {
		main()
		return
	}
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// tokenProviderFunc adapts a function to auth.TokenProvider.
type tokenProviderFunc func(ctx context.Context) (*auth.Token, error)

func (f tokenProviderFunc) Token(ctx context.Context) (*auth.Token, error) { return f(ctx) }

// newTestServer returns a server whose tokens are named after the scopes and valid for an hour.
func newTestServer(scopesSeen *[]string) *metadataServer {
	return &metadataServer{
		email:         testEmail,
		projectID:     "dom-lab",
		projectNumber: "267098479356",
		hostname:      "agent-host",
		now:           func() time.Time { return testNow },
		token: func(ctx context.Context, scopes []string) (*auth.Token, error) {
			if scopesSeen != nil {
				*scopesSeen = scopes
			}
			return &auth.Token{Value: "token-for-" + strings.Join(scopes, ","), Type: "Bearer", Expiry: testNow.Add(time.Hour)}, nil
		},
	}
}

// get sends a request with the metadata flavor header to the server.
func get(server *metadataServer, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Metadata-Flavor", "Google")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

func TestRequestChecks(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"valid", http.MethodGet, map[string]string{"Metadata-Flavor": "Google"}, http.StatusOK},
		{"head", http.MethodHead, map[string]string{"Metadata-Flavor": "Google"}, http.StatusOK},
		{"missing flavor", http.MethodGet, nil, http.StatusForbidden},
		{"wrong flavor", http.MethodGet, map[string]string{"Metadata-Flavor": "Other"}, http.StatusForbidden},
		{"forwarded", http.MethodGet, map[string]string{"Metadata-Flavor": "Google", "X-Forwarded-For": "192.0.2.1"}, http.StatusForbidden},
		{"post", http.MethodPost, map[string]string{"Metadata-Flavor": "Google"}, http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, root+"project/project-id", nil)
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			recorder := httptest.NewRecorder()
			newTestServer(nil).ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Errorf("status = %d, want %d", recorder.Code, test.want)
			}
			if got := recorder.Header().Get("Metadata-Flavor"); got != "Google" {
				t.Errorf("response Metadata-Flavor = %q, want Google", got)
			}
		})
	}
}

func TestEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		target string
		status int
		body   string
	}{
		{"ping", "/", 200, ""},
		{"root", root, 200, ""},
		{"project ID", root + "project/project-id", 200, "dom-lab"},
		{"project number", root + "project/numeric-project-id", 200, "267098479356"},
		{"hostname", root + "instance/hostname", 200, "agent-host"},
		{"universe domain", root + "universe/universe-domain", 200, "googleapis.com"},
		{"email", root + "instance/service-accounts/default/email", 200, testEmail},
		{"email by address", root + "instance/service-accounts/" + testEmail + "/email", 200, testEmail},
		{"scopes", root + "instance/service-accounts/default/scopes", 200, defaultScope + "\n"},
		{"account list", root + "instance/service-accounts/", 200, "default/\n" + testEmail + "/\n"},
		{"account contents", root + "instance/service-accounts/default/", 200, "aliases\nemail\nscopes\ntoken\n"},
		{"other account", root + "instance/service-accounts/other@dom-lab.iam.gserviceaccount.com/email", 404, "Not Found"},
		{"unknown path", root + "instance/zone", 404, "Not Found"},
		{"outside root", "/other", 404, "Not Found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := get(newTestServer(nil), test.target)
			if recorder.Code != test.status || recorder.Body.String() != test.body {
				t.Errorf("got %d %q, want %d %q", recorder.Code, recorder.Body.String(), test.status, test.body)
			}
		})
	}
}

func TestMissingProject(t *testing.T) {
	server := newTestServer(nil)
	server.projectID, server.projectNumber = "", ""
	for _, name := range []string{"project/project-id", "project/numeric-project-id"} {
		if recorder := get(server, root+name); recorder.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", name, recorder.Code)
		}
	}
}

func TestAccountInfo(t *testing.T) {
	want := serviceAccount{Aliases: []string{"default"}, Email: testEmail, Scopes: []string{defaultScope}}

	recorder := get(newTestServer(nil), root+"instance/service-accounts/default/?recursive=true")
	var account serviceAccount
	if err := json.Unmarshal(recorder.Body.Bytes(), &account); err != nil {
		t.Fatalf("invalid JSON %q: %v", recorder.Body.String(), err)
	}
	if recorder.Code != 200 || !slices.Equal(account.Aliases, want.Aliases) || account.Email != want.Email || !slices.Equal(account.Scopes, want.Scopes) {
		t.Errorf("got %d %+v, want 200 %+v", recorder.Code, account, want)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	recorder = get(newTestServer(nil), root+"instance/service-accounts/?recursive=true")
	var listed map[string]serviceAccount
	if err := json.Unmarshal(recorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("invalid JSON %q: %v", recorder.Body.String(), err)
	}
	if len(listed) != 2 || listed["default"].Email != testEmail || listed[testEmail].Email != testEmail {
		t.Errorf("got %+v, want default and %s", listed, testEmail)
	}
}

func TestToken(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantScopes []string
		wantToken  string
	}{
		{"default scope", root + "instance/service-accounts/default/token", []string{defaultScope}, "token-for-" + defaultScope},
		{"scopes", root + "instance/service-accounts/default/token?scopes=a,b", []string{"a", "b"}, "token-for-a,b"},
		{"by address", root + "instance/service-accounts/" + testEmail + "/token", []string{defaultScope}, "token-for-" + defaultScope},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var scopes []string
			recorder := get(newTestServer(&scopes), test.target)
			var response struct {
				AccessToken string `json:"access_token"`
				ExpiresIn   int    `json:"expires_in"`
				TokenType   string `json:"token_type"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("invalid JSON %q: %v", recorder.Body.String(), err)
			}
			if recorder.Code != 200 || response.AccessToken != test.wantToken || response.ExpiresIn != 3600 || response.TokenType != "Bearer" {
				t.Errorf("got %d %+v", recorder.Code, response)
			}
			if !slices.Equal(scopes, test.wantScopes) {
				t.Errorf("scopes = %v, want %v", scopes, test.wantScopes)
			}
			if got := recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
		})
	}
}

func TestParseScopes(t *testing.T) {
	tests := []struct {
		value string
		want  []string
	}{
		{"", []string{defaultScope}},
		{",,", []string{defaultScope}},
		{"a", []string{"a"}},
		{"a,,b,", []string{"a", "b"}},
	}
	for _, test := range tests {
		if got := parseScopes(test.value); !slices.Equal(got, test.want) {
			t.Errorf("parseScopes(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestRequestLogOmitsQuery(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(io.Discard)

	get(newTestServer(nil), root+"instance/service-accounts/default/token?scopes=secret-scope")
	if !strings.Contains(logged.String(), "GET "+root+"instance/service-accounts/default/token 200") {
		t.Errorf("the request was not logged:\n%s", logged.String())
	}
	if strings.Contains(logged.String(), "secret-scope") {
		t.Errorf("the log contains the query:\n%s", logged.String())
	}
}

func TestRequestLogEscapesPath(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(io.Discard)

	get(newTestServer(nil), "/x%0a2026/10/20%2012:00:00%20GET%20/forged%20200%0d%0a%1b[2J")
	if got := strings.Count(logged.String(), "\n"); got != 1 {
		t.Errorf("the log has %d lines, want 1:\n%q", got, logged.String())
	}
	if strings.ContainsAny(strings.TrimSuffix(logged.String(), "\n"), "\r\n\x1b") {
		t.Errorf("the log contains control characters:\n%q", logged.String())
	}
}

func TestHeadHasNoBody(t *testing.T) {
	server := httptest.NewServer(newTestServer(nil))
	defer server.Close()

	request, _ := http.NewRequest(http.MethodHead, server.URL+root+"project/project-id", nil)
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || len(body) != 0 {
		t.Errorf("got %d with body %q, want 200 without body", response.StatusCode, body)
	}
}

func TestPing(t *testing.T) {
	emulator := httptest.NewServer(newTestServer(nil))
	defer emulator.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()
	closed := httptest.NewServer(nil)
	closed.Close()

	if err := ping(strings.TrimPrefix(emulator.URL, "http://")); err != nil {
		t.Errorf("ping(emulator) = %v, want nil", err)
	}
	if err := ping(strings.TrimPrefix(other.URL, "http://")); err == nil {
		t.Error("ping(other server) = nil, want an error")
	}
	if err := ping(strings.TrimPrefix(closed.URL, "http://")); err == nil {
		t.Error("ping(closed) = nil, want an error")
	}
}

func TestTokenExpiry(t *testing.T) {
	tests := []struct {
		name     string
		token    auth.Token
		wantType string
		wantIn   int
	}{
		{"remaining lifetime", auth.Token{Value: "t", Expiry: testNow.Add(90 * time.Second)}, "Bearer", 90},
		{"no expiry", auth.Token{Value: "t"}, "Bearer", 3600},
		{"expired", auth.Token{Value: "t", Expiry: testNow.Add(-time.Minute)}, "Bearer", 0},
		{"token type", auth.Token{Value: "t", Type: "MAC", Expiry: testNow.Add(time.Minute)}, "MAC", 60},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(nil)
			server.token = func(context.Context, []string) (*auth.Token, error) { return &test.token, nil }
			var response struct {
				ExpiresIn int    `json:"expires_in"`
				TokenType string `json:"token_type"`
			}
			recorder := get(server, root+"instance/service-accounts/default/token")
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("invalid JSON %q: %v", recorder.Body.String(), err)
			}
			if response.ExpiresIn != test.wantIn || response.TokenType != test.wantType {
				t.Errorf("got expires_in %d token_type %q, want %d %q", response.ExpiresIn, response.TokenType, test.wantIn, test.wantType)
			}
		})
	}
}

func TestTokenError(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(io.Discard)

	server := newTestServer(nil)
	server.token = func(context.Context, []string) (*auth.Token, error) {
		return nil, errors.New("status code 400: {\n \"error\": \"secret detail\"\n}")
	}
	recorder := get(server, root+"instance/service-accounts/default/token")
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret detail") {
		t.Errorf("the response %q leaks the error", recorder.Body.String())
	}
	if !strings.Contains(logged.String(), "secret detail") {
		t.Errorf("the error was not logged:\n%s", logged.String())
	}
	if got := strings.Count(logged.String(), "\n"); got != 2 {
		t.Errorf("the log has %d lines, want the error and the request:\n%q", got, logged.String())
	}
}

func TestAllowedScopes(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		target  string
		status  int
		body    string
	}{
		{"default scope allowed", []string{"a", defaultScope}, root + "instance/service-accounts/default/token", 200, ""},
		{"default scope not allowed", []string{"a", "b"}, root + "instance/service-accounts/default/token", 400, "Bad Request"},
		{"allowed scope", []string{"a", "b"}, root + "instance/service-accounts/default/token?scopes=b", 200, ""},
		{"allowed scopes", []string{"a", "b"}, root + "instance/service-accounts/default/token?scopes=b,a", 200, ""},
		{"one scope not allowed", []string{"a", "b"}, root + "instance/service-accounts/default/token?scopes=a,c", 400, "Bad Request"},
		{"no restriction", nil, root + "instance/service-accounts/default/token?scopes=c", 200, ""},
		{"scopes endpoint", []string{"a", "b"}, root + "instance/service-accounts/default/scopes", 200, "a\nb\n"},
		{"scopes endpoint unrestricted", nil, root + "instance/service-accounts/default/scopes", 200, defaultScope + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requested []string
			server := newTestServer(&requested)
			server.allowedScopes = test.allowed
			recorder := get(server, test.target)
			if recorder.Code != test.status || (test.body != "" && recorder.Body.String() != test.body) {
				t.Errorf("got %d %q, want %d %q", recorder.Code, recorder.Body.String(), test.status, test.body)
			}
			if test.status == 400 && requested != nil {
				t.Errorf("a token was requested for %v", requested)
			}
		})
	}

	recorder := get(&metadataServer{email: testEmail, allowedScopes: []string{"a", "b"}}, root+"instance/service-accounts/default/?recursive=true")
	var account serviceAccount
	if err := json.Unmarshal(recorder.Body.Bytes(), &account); err != nil {
		t.Fatalf("invalid JSON %q: %v", recorder.Body.String(), err)
	}
	if !slices.Equal(account.Scopes, []string{"a", "b"}) {
		t.Errorf("account scopes = %v, want [a b]", account.Scopes)
	}
}

func TestAllowedCIDRs(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	tests := []struct {
		name    string
		allowed []netip.Prefix
		remote  string
		want    int
	}{
		{"allowed IPv4", allowed, "10.1.2.3:1234", 200},
		{"other IPv4", allowed, "192.168.1.1:1234", 403},
		{"mapped IPv4", allowed, "[::ffff:10.1.2.3]:1234", 200},
		{"allowed IPv6", allowed, "[::1]:1234", 200},
		{"other IPv6", allowed, "[fe80::1]:1234", 403},
		{"unparsable address", allowed, "unknown", 403},
		{"no restriction", nil, "192.168.1.1:1234", 200},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(nil)
			server.allowedCIDRs = test.allowed
			request := httptest.NewRequest(http.MethodGet, root+"project/project-id", nil)
			request.Header.Set("Metadata-Flavor", "Google")
			request.RemoteAddr = test.remote
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Errorf("status = %d, want %d", recorder.Code, test.want)
			}
		})
	}
}

func TestProviderCacheSeeded(t *testing.T) {
	seeded := tokenProviderFunc(func(context.Context) (*auth.Token, error) { return &auth.Token{Value: "seeded"}, nil })
	cache := &providerCache{
		detect:    func([]string) (auth.TokenProvider, error) { return nil, errors.New("detect called") },
		providers: map[string]auth.TokenProvider{defaultScope: seeded},
	}
	token, err := cache.token(context.Background(), []string{defaultScope})
	if err != nil || token.Value != "seeded" {
		t.Errorf("token = %v, %v; want the seeded provider", token, err)
	}
}

func TestServiceAccountEmail(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"external account", `{"type":"external_account","service_account_impersonation_url":"https://iamcredentials.mtls.googleapis.com/v1/projects/-/serviceAccounts/sa-test@dom-lab.iam.gserviceaccount.com:generateAccessToken"}`, testEmail},
		{"impersonated account", `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa-test@dom-lab.iam.gserviceaccount.com:generateAccessToken"}`, testEmail},
		{"service account key", `{"type":"service_account","client_email":"sa-test@dom-lab.iam.gserviceaccount.com"}`, testEmail},
		{"impersonation wins", `{"client_email":"key@p.iam.gserviceaccount.com","service_account_impersonation_url":"https://x/serviceAccounts/sa-test@dom-lab.iam.gserviceaccount.com:generateAccessToken"}`, testEmail},
		{"external account without impersonation", `{"type":"external_account"}`, ""},
		{"unexpected impersonation URL", `{"service_account_impersonation_url":"https://x/other"}`, ""},
		{"invalid JSON", `{`, ""},
		{"empty", ``, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := serviceAccountEmail([]byte(test.json)); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestProviderCache(t *testing.T) {
	var detected atomic.Int32
	var failures atomic.Int32
	cache := &providerCache{detect: func(scopes []string) (auth.TokenProvider, error) {
		detected.Add(1)
		if slices.Equal(scopes, []string{"fail"}) && failures.Add(1) == 1 {
			return nil, errors.New("detection failed")
		}
		return tokenProviderFunc(func(context.Context) (*auth.Token, error) {
			return &auth.Token{Value: strings.Join(scopes, ",")}, nil
		}), nil
	}}
	ctx := context.Background()

	for _, scopes := range [][]string{{"a", "b"}, {"b", "a"}, {"a", "b"}} {
		token, err := cache.token(ctx, scopes)
		if err != nil || token.Value != "a,b" {
			t.Fatalf("token(%v) = %v, %v; want a,b", scopes, token, err)
		}
	}
	if got := detected.Load(); got != 1 {
		t.Errorf("detected %d times for the same scopes in any order, want 1", got)
	}

	if _, err := cache.token(ctx, []string{"c"}); err != nil {
		t.Fatal(err)
	}
	if got := detected.Load(); got != 2 {
		t.Errorf("detected %d times after other scopes, want 2", got)
	}

	if _, err := cache.token(ctx, []string{"fail"}); err == nil {
		t.Error("the detection error was not returned")
	}
	if _, err := cache.token(ctx, []string{"fail"}); err != nil {
		t.Errorf("the detection error was cached: %v", err)
	}
}

func TestProviderCacheBound(t *testing.T) {
	cache := &providerCache{detect: func([]string) (auth.TokenProvider, error) {
		return tokenProviderFunc(func(context.Context) (*auth.Token, error) { return &auth.Token{Value: "t"}, nil }), nil
	}}
	for i := range 10 * maxProviders {
		if _, err := cache.token(context.Background(), []string{strings.Repeat("s", i+1)}); err != nil {
			t.Fatal(err)
		}
		if len(cache.providers) > maxProviders {
			t.Fatalf("%d providers cached after %d scope sets, want at most %d", len(cache.providers), i+1, maxProviders)
		}
	}
}

func TestProviderCacheConcurrent(t *testing.T) {
	var detected atomic.Int32
	cache := &providerCache{detect: func([]string) (auth.TokenProvider, error) {
		detected.Add(1)
		return tokenProviderFunc(func(context.Context) (*auth.Token, error) { return &auth.Token{Value: "t"}, nil }), nil
	}}

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.token(context.Background(), []string{"a"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := detected.Load(); got != 1 {
		t.Errorf("detected %d times, want 1", got)
	}
}

// startServe serves the handler on a local listener and returns its address,
// the function that stops it and the channel with the result of serve.
func startServe(t *testing.T, handler http.Handler, grace time.Duration) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		result <- serve(ctx, &http.Server{Handler: handler}, listener, grace)
	}()
	return listener.Addr().String(), cancel, result
}

// await returns the result of serve, failing the test when it takes too long.
func await(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return")
		return nil
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	address, cancel, result := startServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), time.Second)

	response, err := http.Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	cancel()
	if err := await(t, result); err != nil {
		t.Errorf("serve = %v, want nil", err)
	}
	if connection, err := net.Dial("tcp", address); err == nil {
		connection.Close()
		t.Error("the listener still accepts connections")
	}
}

func TestServeFinishesRequestsInProgress(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	address, cancel, result := startServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "done")
	}), 5*time.Second)

	body := make(chan string, 1)
	go func() {
		response, err := http.Get("http://" + address)
		if err != nil {
			body <- err.Error()
			return
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		body <- string(data)
	}()
	<-started

	cancel()
	select {
	case err := <-result:
		t.Fatalf("serve returned %v while a request was in progress", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	if got := <-body; got != "done" {
		t.Errorf("response = %q, want done", got)
	}
	if err := await(t, result); err != nil {
		t.Errorf("serve = %v, want nil", err)
	}
}

func TestServeStopsAfterGracePeriod(t *testing.T) {
	started := make(chan struct{})
	address, cancel, result := startServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}), 100*time.Millisecond)

	failed := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + address)
		if err == nil {
			response.Body.Close()
		}
		failed <- err
	}()
	<-started

	cancel()
	if err := await(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("serve = %v, want %v", err, context.DeadlineExceeded)
	}
	select {
	case err := <-failed:
		if err == nil {
			t.Error("the request in progress was not interrupted")
		}
	case <-time.After(5 * time.Second):
		t.Error("the request in progress was not interrupted")
	}
}

func TestServeReturnsListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()

	if err := serve(context.Background(), &http.Server{}, listener, time.Second); err == nil {
		t.Error("serve = nil, want the listener error")
	}
}

// writeServiceAccountKey writes a service account key with a generated private key.
func writeServiceAccountKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "dom-lab",
		"private_key_id": "key",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   testEmail,
		"client_id":      "1",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// safeBuffer collects the output of a process while it runs.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// emulator is the test binary running as the emulator process.
type emulator struct {
	address string
	process *os.Process
	exited  <-chan error
	output  *safeBuffer
}

// freePort returns a free TCP port of the loopback interface.
func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return port
}

// runEmulator starts the test binary as the emulator with the arguments and
// the environment on the loopback interface, and returns it once it answers.
func runEmulator(t *testing.T, env []string, args ...string) *emulator {
	t.Helper()
	port := freePort(t)
	e := &emulator{address: "127.0.0.1:" + port, output: &safeBuffer{}}

	command := exec.Command(os.Args[0], args...)
	command.Env = append(os.Environ(), mainEnv+"=1", "GOOGLE_APPLICATION_CREDENTIALS="+writeServiceAccountKey(t), "IMDS_HOST=127.0.0.1", "IMDS_PORT="+port)
	command.Env = append(command.Env, env...)
	command.Stderr = e.output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	e.process, e.exited = command.Process, exited
	t.Cleanup(func() { command.Process.Kill() })

	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			t.Fatalf("the emulator exited before it was ready: %v\n%s", err, e.output.String())
		default:
		}
		if ping(e.address) == nil {
			return e
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the emulator did not answer\n%s", e.output.String())
	return nil
}

// wait returns the exit error of the emulator, failing the test when it does not stop.
func (e *emulator) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-e.exited:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("the emulator did not stop\n%s", e.output.String())
		return nil
	}
}

// runCheck runs the test binary in check mode against the port and returns its exit error.
func runCheck(t *testing.T, port string) error {
	t.Helper()
	command := exec.Command(os.Args[0], "-check")
	command.Env = append(os.Environ(), mainEnv+"=1", "IMDS_PORT="+port)
	return command.Run()
}

// TestSignals runs the emulator as a process and stops it with signals.
func TestSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(signal.String(), func(t *testing.T) {
			e := runEmulator(t, nil)
			if err := e.process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			if err := e.wait(t); err != nil {
				t.Errorf("the emulator exited with %v, want status 0\n%s", err, e.output.String())
			}
			if !strings.Contains(e.output.String(), "shutting down") || !strings.Contains(e.output.String(), "Stopped") {
				t.Errorf("unexpected log:\n%s", e.output.String())
			}
		})
	}

	t.Run("second signal", func(t *testing.T) {
		e := runEmulator(t, nil)

		// A partial request keeps a connection active, so the shutdown waits for it.
		connection, err := net.Dial("tcp", e.address)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if _, err := io.WriteString(connection, "GET / HTTP/1.1\r\nHost: imds\r\n"); err != nil {
			t.Fatal(err)
		}

		if err := e.process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-e.exited:
			t.Fatalf("the emulator exited with %v while a connection was active", err)
		case <-time.After(500 * time.Millisecond):
		}
		if err := e.process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		var exitError *exec.ExitError
		if err := e.wait(t); !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
			t.Errorf("the emulator exited with %v, want status 1\n%s", err, e.output.String())
		}
		if !strings.Contains(e.output.String(), "again, exiting") {
			t.Errorf("unexpected log:\n%s", e.output.String())
		}
	})
}

// TestProcess checks the environment handling and the check mode of the emulator process.
func TestProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	email := func(t *testing.T, address string) string {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+root+"instance/service-accounts/default/email", nil)
		request.Header.Set("Metadata-Flavor", "Google")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body)
	}

	t.Run("email from credentials", func(t *testing.T) {
		e := runEmulator(t, nil)
		if got := email(t, e.address); got != testEmail {
			t.Errorf("email = %q, want %q", got, testEmail)
		}
		if !strings.Contains(e.output.String(), "Serving tokens of "+testEmail+" for project dom-lab on "+e.address) {
			t.Errorf("unexpected log:\n%s", e.output.String())
		}
	})

	t.Run("email override", func(t *testing.T) {
		e := runEmulator(t, []string{"SERVICE_ACCOUNT_EMAIL=other@dom-lab.iam.gserviceaccount.com"})
		if got := email(t, e.address); got != "other@dom-lab.iam.gserviceaccount.com" {
			t.Errorf("email = %q, want the override", got)
		}
	})

	t.Run("allowed scopes", func(t *testing.T) {
		e := runEmulator(t, []string{"IMDS_ALLOWED_SCOPES=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/cloud-platform"})
		for target, want := range map[string]int{
			root + "instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/other": http.StatusBadRequest,
			root + "instance/service-accounts/default/scopes":                                             http.StatusOK,
		} {
			request, _ := http.NewRequest(http.MethodGet, "http://"+e.address+target, nil)
			request.Header.Set("Metadata-Flavor", "Google")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != want {
				t.Errorf("%s: status = %d, want %d", target, response.StatusCode, want)
			}
		}
		if !strings.Contains(e.output.String(), "Allowed scopes: https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/devstorage.read_only") {
			t.Errorf("unexpected log:\n%s", e.output.String())
		}
	})

	t.Run("allowed CIDRs", func(t *testing.T) {
		e := runEmulator(t, []string{"IMDS_ALLOWED_CIDRS=127.0.0.0/8, ::1/128"})
		if got := email(t, e.address); got != testEmail {
			t.Errorf("email = %q, want %q", got, testEmail)
		}
		if !strings.Contains(e.output.String(), "Allowed client networks: [127.0.0.0/8 ::1/128]") {
			t.Errorf("unexpected log:\n%s", e.output.String())
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		command := exec.Command(os.Args[0])
		command.Env = append(os.Environ(), mainEnv+"=1", "GOOGLE_APPLICATION_CREDENTIALS="+writeServiceAccountKey(t), "IMDS_HOST=127.0.0.1", "IMDS_PORT="+freePort(t), "IMDS_ALLOWED_CIDRS=10.0.0.1")
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("the emulator started with an invalid CIDR\n%s", output)
		}
		if !strings.Contains(string(output), "Invalid IMDS_ALLOWED_CIDRS") {
			t.Errorf("unexpected output:\n%s", output)
		}
	})

	t.Run("check", func(t *testing.T) {
		e := runEmulator(t, nil)
		_, port, _ := net.SplitHostPort(e.address)
		if err := runCheck(t, port); err != nil {
			t.Errorf("check against the emulator = %v, want nil", err)
		}
		if err := runCheck(t, freePort(t)); err == nil {
			t.Error("check against a closed port = nil, want an error")
		}
	})
}
