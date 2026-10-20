# GCE IMDS Emulator

The IMDS emulator is a token proxy. It serves the endpoints of the Compute Engine metadata server (IMDS) and answers token requests with access tokens it obtains through its own Application Default Credentials (ADC).

A client that runs outside Compute Engine and supports only the metadata server, or cannot use the credential type at hand, gets the tokens of a service account without a credentials file of its own. The emulator holds the credentials. The client only needs the address of the emulator in `GCE_METADATA_HOST` and `GCE_METADATA_IP`, which the Google client libraries use instead of the address of the metadata server.

Any credential type supported by ADC works, including Workload Identity Federation (WIF) with an X.509 client certificate and service account impersonation.

The project is licensed under the MIT License, see `LICENSE`.

## Disclaimer

The code and documentation of this project were created with AI assistance. Claude Opus 5.5 created the code. Claude Fable 5.1 performed the security review and wrote the fixes. The code has been reviewed and tested by a human.

## Configuration

The emulator reads its settings from the environment:

| Variable | Default | Meaning |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | ADC search order | Credentials file used to obtain the tokens |
| `GOOGLE_API_CERTIFICATE_CONFIG` | none | Certificate configuration of X.509 credentials |
| `SERVICE_ACCOUNT_EMAIL` | taken from the credentials | Email of the service account reported to clients |
| `PROJECT_ID` | project of the credentials | Value of `project/project-id` |
| `PROJECT_NUMBER` | none | Value of `project/numeric-project-id` |
| `IMDS_HOSTNAME` | host name of the container | Value of `instance/hostname` |
| `IMDS_HOST` | all interfaces | Address the server binds |
| `IMDS_PORT` | `8080` | Port the server listens on |
| `IMDS_ALLOWED_SCOPES` | all scopes | Comma separated scopes that token requests may use |

With `IMDS_ALLOWED_SCOPES`, a token request with a scope outside the list is rejected with the status 400 before any token is requested, and the scopes endpoints report the list instead of the `cloud-platform` scope. A token request without the `scopes` parameter asks for the `cloud-platform` scope, so the list must contain it for such requests to succeed. The variable limits what the clients of an emulator on a host can obtain, where the network does not separate the clients.

The service account email is taken from the impersonation URL of the credentials file, or from `client_email` of a service account key. An external account without impersonation has no email in the file, so it needs `SERVICE_ACCOUNT_EMAIL`. The emulator does not start without an email or without valid ADC.

The option `-check` turns the binary into a health check. It sends the metadata ping to `IMDS_HOST`, or to `127.0.0.1` when the variable is empty, on `IMDS_PORT`, and exits with status 0 when the emulator answers within 2 seconds.

## Endpoints

All paths are below `/computeMetadata/v1/`. The service account is named `default` or by its email.

| Path | Response |
|---|---|
| `/` and `/computeMetadata/v1/` | Empty ping response |
| `instance/service-accounts/` | Account list; JSON with `?recursive=true` |
| `instance/service-accounts/default/` | Account attributes; JSON with `?recursive=true` |
| `instance/service-accounts/default/token` | Access token as JSON with `access_token`, `expires_in` and `token_type`; the scopes come from the comma separated `scopes` query parameter, `cloud-platform` without it; 400 for a scope outside `IMDS_ALLOWED_SCOPES` |
| `instance/service-accounts/default/email` | Service account email |
| `instance/service-accounts/default/scopes` | `IMDS_ALLOWED_SCOPES`, or the `cloud-platform` scope |
| `project/project-id` | Project ID, 404 when unknown |
| `project/numeric-project-id` | Project number, 404 when unknown |
| `instance/hostname` | Host name |
| `universe/universe-domain` | `googleapis.com` |

Every other path returns 404. Methods other than `GET` and `HEAD` return 405. Requests without the header `Metadata-Flavor: Google`, or with `X-Forwarded-For`, return 403. Every response carries `Metadata-Flavor: Google`.

The emulator logs one line per request with the method, the path and the status. It never logs the query string or the token.

## Implementation

The emulator is a single Go program, `main.go`, with its unit tests in `main_test.go`. It uses the standard library for the HTTP server and two modules besides it:

- `cloud.google.com/go/auth` finds the ADC and obtains, caches and refreshes the tokens.
- `golang.org/x/crypto/x509roots/fallback` embeds fallback root certificates, and the standard package `time/tzdata` embeds fallback time zone data.

The program consists of the following parts:

- **`metadataServer`:** the HTTP handler. It checks the request, maps the email alias to `default`, and answers the endpoints. It gets tokens through a function field and the time through a clock field, so the tests replace both.
- **`providerCache`:** keeps one token provider per set of scopes. The scopes are sorted, so their order in the query does not matter. Detection errors are not cached, so a later request retries.
- **`serviceAccountEmail`:** extracts the email from the credentials file.
- **`serve`:** runs the server until its context is canceled, then shuts it down within a grace period.
- **`main`:** reads the environment, detects the ADC, handles the signals, and starts the server or runs the check.

The token response reports the remaining lifetime of the token in `expires_in`. A token without expiry is reported with 3600 seconds.

### Embedded root certificates and time zone data

The embedded root certificates are the Mozilla NSS trust store, the root store of Firefox, as of the version of `golang.org/x/crypto/x509roots/fallback` in `go.sum`. Go uses them only when it finds no root certificates on the system. On Linux it reads the first existing file of a fixed list, starting with `/etc/ssl/certs/ca-certificates.crt`, and the files in `/etc/ssl/certs` and `/etc/pki/tls/certs`. The variables `SSL_CERT_FILE` and `SSL_CERT_DIR` replace the file list and the directory list. When neither yields a certificate, Go uses the embedded roots. `GODEBUG=x509usefallbackroots=1` makes Go use the embedded roots even when the system has its own.

The roots verify the TLS connections of the emulator to the Google token endpoints, which the authentication library makes without its own root pool.

The embedded time zone data is the zone database of the Go release that built the binary. Go reads a zone from the files of the system first, from `/usr/share/zoneinfo/` and the other system zone directories, and uses the embedded data only for a zone it does not find there. The emulator uses a zone only for the timestamps of its log, which are in local time. The local time zone comes from the variable `TZ`, and from `/etc/localtime` without it. When neither names a zone that loads, the timestamps are in UTC. The embedded data therefore matters only when `TZ` names a zone that the system has no file for.

The image `gcr.io/distroless/static-debian13` contains the root certificate bundle of Debian and the zone files, so in the container the emulator uses those and not the embedded data. The embedded data takes effect when the binary runs on a system without them, such as a `scratch` image.

### Image

The image is built in two stages by the `Dockerfile`. The first stage runs the unit tests and builds a static binary with `CGO_ENABLED=0`. The second stage copies the binary to `gcr.io/distroless/static-debian13`, which runs it as its entry point.

## Architectural decisions

- **Go with a static binary.** The binary has no runtime dependencies, so it runs on a distroless image without a shell, a package manager or an interpreter. The embedded root certificates and time zone data are fallbacks, so the binary also works on a system without these files, while the files of the system take precedence where they exist.
- **ADC as the only credential source.** The emulator delegates the credential handling to the Google authentication library and supports every credential type the library does. It reads the X.509 certificate and key through the certificate configuration, so certificates renewed in place are used without a restart of the emulator.
- **Token caching in the library.** The emulator stores no tokens of its own. Each token provider caches its token and refreshes it before expiry, so repeated client requests do not reach the token service.
- **Bounded provider cache.** At most 16 providers are kept. When the limit is reached, all of them are dropped. A client therefore cannot grow the memory of the emulator by requesting many scope sets, and the simple eviction suffices because clients use few scope sets.
- **Subset of the metadata server.** The emulator serves the endpoints that the Google client libraries use for authentication and project detection. Other paths return 404 instead of made up values, so a client that depends on them fails visibly.
- **Request checks of the metadata server.** The emulator rejects requests without the flavor header and proxied requests, as the metadata server does. This protects against requests forged by a browser or forwarded by a proxy, but it does not authenticate the client.
- **Network as the trust boundary.** Every client that reaches the port gets the tokens of the service account. The emulator therefore publishes no port in a container setup, and binds the loopback interface through `IMDS_HOST` when it runs on a host. On a host, `IMDS_ALLOWED_SCOPES` limits the tokens to the scopes the local clients need.
- **No error details to clients.** A failed token request returns a generic 500. The details go to the log, where only the operator sees them.
- **Signal handling as PID 1.** The emulator runs as the first process of its container, which receives no default signal handling from the kernel. It handles `SIGTERM` and `SIGINT` itself: the first signal stops accepting connections and lets the requests in progress finish for up to 20 seconds, then the emulator exits with status 0. A second signal makes it exit with status 1 at once. The stop grace period of the container must exceed 20 seconds.
- **Health check in the same binary.** The distroless image has no shell or HTTP client, so the binary checks itself with `-check`. The check uses the same ping as the clients.
- **Tests in the image build.** The unit tests run in the build stage, so a failing test stops the build of the image.
- **Unprivileged port.** The default port 8080 does not require privileges, and clients include it in `GCE_METADATA_HOST`.

## Build the container image

The build needs only Docker. The `Dockerfile` runs the unit tests and builds the binary in a Go toolchain image, so the build host needs no Go installation. The image runs on the platform of the build host.

Clone the repository and build the image with the tag `gce-imds-emulator:latest`:

```bash
git clone https://github.com/skoszewski/gce-imds-emulator.git
cd gce-imds-emulator
docker build --pull -t gce-imds-emulator:latest .
```

The option `--pull` fetches the current base images instead of the ones cached by an earlier build. A failing unit test stops the build.

To use the image on another host without a registry, save it to an archive on the build host:

```bash
docker save -o gce-imds-emulator.tar gce-imds-emulator:latest
```

Copy the archive to the other host and load it there:

```bash
docker load -i gce-imds-emulator.tar
```

To push it to a registry instead, tag it with the registry path and push it, replacing `REGISTRY` with the registry host and path:

```bash
docker tag gce-imds-emulator:latest REGISTRY/gce-imds-emulator:latest
docker push REGISTRY/gce-imds-emulator:latest
```

## Run and test

Run the emulator on its own network with the credentials directory mounted, replacing `/etc/imds-emulator` with the directory of the credentials files:

```bash
docker network create imds
docker run -d --name imds-emulator --network imds \
    -v /etc/imds-emulator:/etc/imds-emulator:ro \
    -e GOOGLE_APPLICATION_CREDENTIALS=/etc/imds-emulator/cred.json \
    -e GOOGLE_API_CERTIFICATE_CONFIG=/etc/imds-emulator/certificate_config.json \
    gce-imds-emulator:latest
```

Request a token from a container on the same network:

```bash
docker run --rm --network imds curlimages/curl \
    -s -H "Metadata-Flavor: Google" \
    http://imds-emulator:8080/computeMetadata/v1/instance/service-accounts/default/token
```

Run the unit tests on a workstation with Go:

```bash
go test -race ./...
```

The tests cover the request checks, the endpoints, the scope parsing, the allowed scopes, the token response, the request log, the provider cache, the extraction of the email, the shutdown, the health check, and runs of the emulator as a process stopped with real signals.
