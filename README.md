# mini-acme

> [Russian version](README_RU.md)

> [China version](README_CN.md)

**mini-acme** is a utility for automatic ACME (RFC 8555) certificate management, written in pure C using the **crypery** (HTTPS Library) library.

For the Let's Encrypt certificate authority, the utility requests a certificate via the ACME protocol using the **HTTP-01** domain ownership validation method: a special validation file `/.well-known/acme-challenge/<token>` is served on port 80, which the CA server requests over HTTP.

## Description

When mini-acme starts:

1. Creates (or loads from the cache) an ACME account with an RSA-2048 key.
2. Requests an RSA-2048 certificate from Let's Encrypt for one or more domains: the first `-domain` is the primary (CN + cache file name), all domains are listed in the SAN extension.
3. Passes domain ownership validation via HTTP-01 for every domain: starts an HTTP server on port 80 that serves the validation files (all other HTTP requests are redirected to HTTPS).
4. Saves the issued certificate (full chain: leaf + intermediates) and the key to the cache directory and exits - no HTTPS server is started.

The account key and issued certificates are stored in a local cache directory (default: `certs/`): `<primary>.pem` (key + full chain), `<primary>.crt` (full chain), `<primary>.key` (key). A restart reuses the cached certificate while it is valid for more than 30 days **and** its SAN covers all requested domains; otherwise a new certificate is issued.

## Project Features

- **Pure C, no external crypto libraries** - the entire TLS stack (TLS 1.2/1.3, AES-128-GCM, SHA-256, HMAC-SHA256, HKDF, RSA-2048, ECDH P-256/X25519, X.509) is implemented inside the crypery library.
- **Full ACME cycle**: account creation, multi-domain certificate order, HTTP-01 validation for every domain, and retrieval.
- **Multi-domain (SAN) certificates**: repeat `-domain` up to 8 times (e.g. apex + `www`) - all names land in a single certificate.
- **Full-chain certificates**: the saved `.crt`/`.pem` files contain the leaf plus the intermediates, so browsers build the chain without errors.
- **Cross-platform**: Windows (Winsock2/WinAPI) and POSIX (BSD sockets, pthreads) - the same source code.
- **One-shot operation**: obtains the certificate and exits - no daemons, no open ports left behind.
- **Caching**: a restart does not create a new account or request a new certificate while the cached one is valid for more than 30 days and covers all requested domains; a stale cache (expiring or missing a SAN name) triggers a reissue.
- **Minimal dependencies**: only the standard C library, pthreads (POSIX), and zlib (gzip compression in the HTTP module).
- **Safe by default**: the Let's Encrypt staging environment is used by default so as not to exhaust the production CA rate limits.

## Modules Used

| Module | Purpose |
|--------|---------|
| **crypery** | A network stack in pure C: TLS 1.2/1.3 crypto layer (`tls`), OpenSSL-compatible wrapper layer (`ssl`), HTTP/1.1 server (`http`), and HTTP/HTTPS client (`url`). All cryptographic algorithms are implemented from scratch; used for ACME requests (the `url` client) and RSA key generation/signing (the `tls` module). |
| **utilery** | A collection of basic C libraries: a JSON parser (`json` - parsing ACME server responses), a logging module (`log`), a settings module (`sett`), and the `ecma` library (UTF-8 codec, regular expressions, string buffer). No external dependencies. |
| **zlib** | Compression library; used by the `http` module of crypery for gzip compression of responses (optional, disabled with the `HTTP_NO_GZIP` flag). |

## Compilation

### Windows (build_acme.bat)

MinGW is required (gcc in PATH). Run:

```bat
build_acme.bat
```

Result: `mini-acme.exe` in the project root.

### Linux (build_acme.sh)

The build is performed inside a Docker container with gcc (the `gcc:13` image), so only Docker is required on the host. Run:

```bash
bash build_acme.sh
```

Result: the `mini-acme` binary (ELF, x86-64) is copied to the project root.

The container image can be overridden with the `IMAGE` environment variable (e.g., `IMAGE=gcc:14 bash build_acme.sh`).

## Usage

```
mini-acme [-domain <name>]... [-dir <acme-directory-url>] [-cache <dir>] [-email <addr>] [-h]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `-domain <name>` | Domain to include in the certificate (repeatable, up to 8; first = primary: CN + cache file name, all = SAN) | hostname |
| `-dir <url>` | ACME directory URL of the CA | Let's Encrypt staging |
| `-cache <dir>` | Cache directory (account key, certificates) | `certs` |
| `-email <addr>` | Contact email for the ACME account | `admin@example.com` |
| `-h`, `-help` | Help | - |

### Requirements

- Every domain must be **publicly accessible** - its A/AAAA record must point to the machine where the utility is running, otherwise the HTTP-01 validation will not pass.
- Inbound port **80** (HTTP-01) must be open.
- Permission to bind to port 80 (on Linux - run as root or with `CAP_NET_BIND_SERVICE`).

### Examples

```bash
# Certificate for example.com in the staging environment (default)
mini-acme -domain example.com

# Apex + www in one certificate, Let's Encrypt production environment
mini-acme -domain example.com -domain www.example.com -dir https://acme-v02.api.letsencrypt.org/directory

# Custom cache directory and email
mini-acme -domain example.com -cache /var/lib/mini-acme -email admin@example.com
```

### Session Example

```
Domains (2): example.com www.example.com
Obtaining certificate for example.com ...
Certificate valid until: 2026-12-20 12:00:00 UTC
Certificate saved to certs/example.com.pem
Done.
```

The program exits after the certificate is obtained. To force a reissue (e.g. after adding a domain), delete the primary-domain cache files (`certs/<primary>.pem`, `.crt`, `.key`) and run again.

## License

GNU AGPL v3 (Affero GPL)
