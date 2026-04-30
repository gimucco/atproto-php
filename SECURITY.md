# Security

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public issue.

Email **info@gimucco.com** with:
- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any suggested mitigation

You should receive an acknowledgement within 72 hours. We aim to publish a fix and disclosure within 30 days for high-severity issues.

## Threat model

This library implements an OAuth 2.1 client. It:
- Holds long-lived refresh tokens and DPoP private keys for each authenticated user
- Makes outbound HTTP requests to user-controlled hosts during the resolution chain
- Authenticates to the authorization server with an ES256 private key

It does **not**:
- Run as an OAuth provider/server
- Handle untrusted token validation (the library validates its own tokens, not third-party ones)
- Process user-uploaded content

The primary risks are: leaking tokens or DPoP keys at rest, leaking the client private key, SSRF via the resolution chain, and accepting tokens for an unintended user (sub-claim mismatch).

## SSRF protection

The AT Protocol resolution chain (handle → DID → PDS → auth server) follows several user-controlled values. Without protection, a malicious handle or DID document could direct the library to make HTTP requests against internal infrastructure — cloud metadata services like `169.254.169.254`, internal APIs, databases.

`OAuthClient` wraps the supplied PSR-18 HTTP client in a guard that resolves each destination hostname and rejects requests to:

- IPv4 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`, `::1`
- Link-local: `169.254.0.0/16`, `fe80::/10` — including AWS/GCP metadata services
- CGNAT: `100.64.0.0/10`
- IPv6 unique-local: `fc00::/7`
- Documentation/benchmarking: `192.0.0.0/24`, `198.18.0.0/15`, `192.0.2.0/24`, `203.0.113.0/24`
- Zero address, multicast, reserved

Non-`http`/`https` schemes are also rejected. Blocked requests raise `NetworkException`.

This is on by default. Disable only for tests against mock servers:

```php
new OAuthClient(
    // ...
    ssrfProtection: false,
);
```

### TOCTOU window

The guard does a pre-flight DNS lookup, then trusts the underlying HTTP client to connect. Between those two steps, a malicious DNS server can rebind the hostname (very low TTL: first answer public, second answer `127.0.0.1`).

PSR-18 does not expose a portable way to pin a connection to a specific resolved IP. If you need stronger guarantees, configure your transport to do so:

```php
// Guzzle: pin the hostname to a specific IP for the lifetime of the request
$client = new \GuzzleHttp\Client([
    'curl' => [
        CURLOPT_RESOLVE => ['example.com:443:1.2.3.4'],
    ],
]);
```

For most deployments the pre-flight check is sufficient. DNS rebinding requires the attacker to control the authoritative DNS for the malicious handle/DID and serve adversarial responses — a real but narrow attack class.

## Token and key storage

Sessions hold three secrets per user:
- The access token (short-lived, ~5–30 min)
- The refresh token (up to 180 days)
- The DPoP private key (lifetime of the session)

The refresh token and DPoP key are the high-value targets — together they let an attacker impersonate the user until the session expires.

### Encryption at rest

`FileSessionStore` and `PdoSessionStore` accept a `passphrase` parameter. When provided, all three secrets are encrypted with `sodium_crypto_secretbox` (XSalsa20-Poly1305) before storage:

```php
new FileSessionStore('/var/app/sessions', passphrase: 'strong-random-passphrase');
```

If you don't provide a passphrase, a warning is logged and storage proceeds in plaintext. This is acceptable only if the storage layer itself is encrypted (full-disk encryption, encrypted database volume).

### Choosing a passphrase

The passphrase is used as input to `sodium_crypto_generichash()` to derive a 32-byte key. Any high-entropy value works:
- 32+ random bytes from a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- A long random string in an environment variable
- A value derived from your application's existing secret material

Never hard-code the passphrase. Never check it into version control.

### Rotating the passphrase

Passphrase rotation is not yet automated. To rotate:
1. Decrypt all sessions with the old passphrase
2. Re-encrypt with the new passphrase
3. Atomically swap

In practice, the simplest path is to revoke all sessions and require users to re-authenticate.

## Client private key

The ES256 private key in `ClientConfig::privateKey` is the long-lived credential that authenticates **your application** (not individual users) to authorization servers. If it leaks, anyone can impersonate your app to any AT Protocol auth server until you remove the corresponding public key from your published JWKS.

- Store the PEM file outside of the web root with restrictive permissions (`chmod 0400`)
- Inject via environment variable or secrets manager in production
- Never commit it
- Rotate periodically by adding a new key to your JWKS, switching the client to sign with the new key, and removing the old one once existing sessions have expired (per the AT Protocol spec, sessions are bound to a specific key by `kid`/JWK thumbprint)

The library reads the key once at `OAuthClient` construction. Keep the configured `OAuthClient` instance ephemeral if you can — for example, construct it per request rather than as a long-lived singleton — to limit the window during which the key sits in process memory.

## Sub-claim validation

After token exchange, the library verifies that the `sub` claim returned by the authorization server matches the DID resolved at the start of the flow. If they differ — meaning the auth server returned tokens for a different account than the user requested — `completeAuthorization()` throws an `AuthorizationException`.

This check is automatic and not configurable.

## State validation

The OAuth `state` parameter is generated as 32 random bytes (base64url-encoded) and stored server-side via the `StateStoreInterface` with a 10-minute TTL. The callback compares the returned state against stored entries — unknown or expired states throw `AuthorizationException`.

If you supply your own `state` to `beginAuthorization()`, ensure it is unguessable and unique per authorization attempt. Reusing state values across users or sessions defeats the protection.

## Issuer validation

The `iss` parameter on the OAuth callback is checked against the authorization server discovered during `beginAuthorization()`. Mismatches throw `AuthorizationException`. This protects against mix-up attacks where an attacker tricks the user's browser into completing one server's flow with another server's response.

## HTTPS

All AT Protocol endpoints are HTTPS. The library refuses non-HTTPS URLs in `redirect_uri` (except `localhost` and `127.0.0.1` for local development) and rejects non-`http`/`https` schemes in the SSRF guard.

Do not disable TLS verification in production HTTP clients (`'verify' => false` in Guzzle). If you do for development, ensure the same code path is impossible in production builds.

## Refresh-token rotation

When the authorization server returns a new refresh token alongside a new access token, the library replaces the stored refresh token. If the server does not rotate (returns no new refresh token), the existing one is kept.

Rotation is the server's choice, not the client's. The library handles whichever the server does.

## Logging

The library logs nonce retries (debug), unencrypted-storage warnings (warning), and refresh failures (error). It never logs:
- Access tokens
- Refresh tokens
- DPoP private keys
- Client assertions
- Authorization codes

If you wrap the library's HTTP client with your own logging middleware, audit it to ensure the same fields are not captured.
