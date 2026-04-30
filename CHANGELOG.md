# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-05-01

### Added

- `Session::authenticatedRawRequest()` — sends a raw byte body with a caller-controlled `Content-Type`. Use for endpoints that take binary input (e.g. `com.atproto.repo.uploadBlob` for image and video uploads). Same DPoP, nonce-retry, and auto-refresh guarantees as `authenticatedRequest()`. The existing JSON-encoding behaviour of `authenticatedRequest()` is unchanged.

### Changed

- Internal: extracted a private `Session::dispatch()` helper that owns the "refresh-if-near-expiry → send" plumbing shared by both request methods. No public-API impact.

## [0.1.1] - 2026-04-30

### Added

- `ClientConfig::$defaultAuthorizationServer` — configurable auth server URL for the server-first authorization flow. Defaults to `https://bsky.social`; override to point a "Sign in" button at a self-hosted PDS or another atproto host without changing per-call code.

### Changed

- `OAuthClient::beginAuthorization()` now reads its server-first fallback from `ClientConfig::$defaultAuthorizationServer` instead of a hardcoded `https://bsky.social`. The default URL is unchanged, so existing callers see no behaviour change.

### Fixed

- `AuthServerResolver` now normalises issuer URLs before constructing the `.well-known/oauth-authorization-server` discovery URL. Previously, an issuer URL containing a query string or fragment (e.g. `https://example.com?x=y`) would produce a malformed fetch URL. Trailing slashes are still stripped; ports and paths are preserved (per RFC 8414); query strings, fragments, and non-`http(s)` schemes are now explicitly rejected with a clear `ResolutionException`.

### Documentation

- README "Step 1" reorganised to clearly distinguish identity-first vs server-first flows and show how to target a non-Bluesky auth server.

## [0.1.0] - 2026-04-30

### Added

- Initial release
- Confidential-client OAuth 2.1 flow with PKCE, DPoP, and PAR
- Two authorization modes:
    - Identity-first — pass a handle/DID, the library resolves it and pre-fills `login_hint`
    - Server-first — no handle required, redirect straight to the auth server (default `https://bsky.social`) and let the user pick their account there
- Handle and DID resolution (`did:plc` via `plc.directory`, `did:web`)
- Client metadata and JWKS generation:
    - `ClientMetadataBuilder` programmatic API
    - `bin/generate-metadata` CLI for producing static `.json` files from a config file
- Automatic RFC 7638 JWK thumbprint as `kid` on every key (matches reference atproto clients; lets auth servers map JWTs to JWKS unambiguously)
- Session storage interface with three shipped implementations: `InMemory*`, `File*`, `PDO*` (MySQL / PostgreSQL / SQLite schemas included)
- Encryption at rest for tokens and DPoP keys (libsodium)
- Automatic token refresh on near-expiry
- SSRF protection on outgoing HTTP requests (blocks private, loopback, link-local, CGNAT, and reserved IP ranges; can be opted out for testing)
- Strict P-256 byte padding for JWK `x`/`y`/`d` (avoids one-in-256 keys producing 31-byte coordinates that strict parsers reject)
- PSR-3 logging hook with full error-response capture for failed auth-server calls
- Typed exception hierarchy: `AtprotoException` → `ResolutionException`, `AuthorizationException` → `TokenException`, `DpopException`, `SessionException`, `ConfigurationException`, `NetworkException`
- Full PHPStan level 8 compliance, PER-CS 2.0 code style
