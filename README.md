# gimucco/atproto-php

**AT Protocol OAuth 2.1 client for PHP — PKCE, DPoP, and PAR support for authenticating with Bluesky and other atproto services.**

[![Latest Version](https://img.shields.io/packagist/v/gimucco/atproto-php.svg)](https://packagist.org/packages/gimucco/atproto-php)
[![PHP Version](https://img.shields.io/packagist/php-v/gimucco/atproto-php.svg)](https://packagist.org/packages/gimucco/atproto-php)
[![License](https://img.shields.io/github/license/gimucco/atproto-php.svg)](https://github.com/gimucco/atproto-php/blob/main/LICENSE)
[![CI](https://github.com/gimucco/atproto-php/actions/workflows/ci.yml/badge.svg)](https://github.com/gimucco/atproto-php/actions/workflows/ci.yml)

---

## What this is (and isn't)

This library handles **OAuth 2.1 authentication** with any AT Protocol Personal Data Server (PDS). It gives you an authenticated session you can use to make API calls.

**This is OAuth only.** It does not implement Bluesky-specific operations like posting, fetching feeds, or managing profiles. For that, see the companion library (coming soon).

## Why use this

Existing PHP libraries for AT Protocol only support the deprecated App Password flow. App Passwords are being phased out. The AT Protocol mandates a strict OAuth 2.1 profile that combines several features most OAuth libraries don't handle together:

- **PKCE** (S256 only) — Proof Key for Code Exchange
- **DPoP** — Demonstrating Proof of Possession, with mandatory server-issued nonces
- **PAR** — Pushed Authorization Requests
- **`private_key_jwt`** — Client authentication via signed JWTs
- **Decentralized discovery** — Handle → DID → PDS → Authorization Server

This library handles all of it.

## Requirements

- PHP 8.1+
- Extensions: `json`, `curl`, `openssl`, `sodium`
- A PSR-18 HTTP client (Guzzle recommended)
- An HTTPS domain where you can host two JSON files (client metadata and JWKS)

## Installation

```bash
composer require gimucco/atproto-php

# Recommended: Guzzle as the HTTP client
composer require guzzlehttp/guzzle
```

## Quickstart

```php
<?php

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\OAuthClient;
use Gimucco\Atproto\Storage\FileSessionStore;
use Gimucco\Atproto\Storage\FileStateStore;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;

// 1. Configure
$config = new ClientConfig(
    clientId: 'https://your-app.com/client-metadata.json',
    redirectUri: 'https://your-app.com/callback',
    scope: 'atproto transition:generic',
    clientName: 'My App',
    jwksUri: 'https://your-app.com/jwks.json',
    privateKey: file_get_contents('/path/to/private.pem'),
);

// 2. Create the OAuth client
$factory = new HttpFactory();
$oauth = new OAuthClient(
    config: $config,
    sessionStore: new FileSessionStore('/var/app/sessions', 'encryption-passphrase'),
    stateStore: new FileStateStore('/var/app/states', 'encryption-passphrase'),
    httpClient: new Client(),
    requestFactory: $factory,
    streamFactory: $factory,
);

// 3. Start login — redirect the user
$authUrl = $oauth->beginAuthorization('alice.bsky.social');
header('Location: '.$authUrl);

// 4. Handle callback (in your callback endpoint)
$session = $oauth->completeAuthorization($_GET['code'], $_GET['state'], $_GET['iss']);

// 5. Make authenticated requests
$response = $session->authenticatedRequest(
    'GET',
    $session->pdsUrl.'/xrpc/com.atproto.server.getSession',
);

echo $response->getBody(); // {"did":"did:plc:...","handle":"alice.bsky.social",...}
```

## Concepts

### Client Metadata Document

AT Protocol OAuth uses a URL as the `client_id`. The authorization server fetches this URL to learn about your application. You host a JSON document containing your app name, redirect URIs, and public key. Use `ClientMetadataBuilder::fromConfig()` to generate it.

### JWKS (JSON Web Key Set)

Confidential clients authenticate using `private_key_jwt` — signing a JWT with an ES256 private key. The corresponding public key is published as a JWKS document. Use `ClientMetadataBuilder::jwksFromConfig()` to generate it.

### DPoP (Demonstrating Proof of Possession)

Every token and API request includes a DPoP proof — a short-lived JWT proving the request came from the holder of a specific key. This library handles DPoP automatically, including the mandatory server nonce exchange (the "double-call" pattern).

### Session Storage

Sessions hold access tokens, refresh tokens, and DPoP keys. This library provides three storage backends. See [Session Storage](#session-storage) below.

For deeper reading, see the [AT Protocol OAuth specification](https://atproto.com/specs/oauth) and the [OAuth client implementation guide](https://docs.bsky.app/docs/advanced-guides/oauth-client).

## Generating your client keypair

Generate an ES256 (P-256) private key:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
```

This key is used for two things:
1. **Client assertion** — authenticating to the token endpoint
2. **JWKS** — publishing the public key for the authorization server to verify

Keep `private.pem` secret. Never commit it to version control.

## Hosting client metadata and JWKS

You need to serve two JSON documents at stable HTTPS URLs: `client-metadata.json` and `jwks.json`. Their contents are static for any given app, derived from your config and key.

Generate them with the bundled CLI tool:

```bash
bin/generate-metadata --config=path/to/config.php --output=path/to/public
```

This writes `client-metadata.json` and `jwks.json` to the output directory. Re-run after any config or key change. The output files are static — serve them directly via Nginx, Apache, or any CDN. No PHP needed at request time.

For example

```bash
bin/generate-metadata --config=examples/config.php --output=examples/public
```

**Important:** The `client_id` value in your config must exactly match the URL where `client-metadata.json` is hosted.

If you'd rather generate them in your own application code (e.g., during a deploy hook), the underlying API is `ClientMetadataBuilder::fromConfig($config)` and `ClientMetadataBuilder::jwksFromConfig($config)` — both return associative arrays you can `json_encode` and write wherever you like.

## The full OAuth flow

### Step 1: Resolve and start authorization

```php
// The user provides their handle (or DID)
$handle = 'alice.bsky.social';

// This resolves the handle → DID → PDS → auth server, generates PKCE + DPoP,
// sends a PAR request, and returns the authorization URL
$authUrl = $oauth->beginAuthorization($handle);

// Redirect the user's browser
header('Location: '.$authUrl);
exit;
```

### Step 2: Handle the callback

```php
// The authorization server redirects back with code, state, and iss
$session = $oauth->completeAuthorization(
    code: $_GET['code'],
    state: $_GET['state'],
    iss: $_GET['iss'],
);

// $session->did    — "did:plc:..."
// $session->handle — "alice.bsky.social"
// $session->pdsUrl — "https://bsky.social" (or wherever their PDS is)
```

The library validates:
- The `state` matches a pending authorization
- The `iss` matches the expected authorization server
- The `sub` in the token response matches the resolved DID

## Making authenticated requests

```php
// GET request
$response = $session->authenticatedRequest(
    'GET',
    $session->pdsUrl.'/xrpc/com.atproto.server.getSession',
);

// POST request with JSON body
$response = $session->authenticatedRequest(
    'POST',
    $session->pdsUrl.'/xrpc/com.atproto.repo.createRecord',
    [
        'repo' => $session->did,
        'collection' => 'app.bsky.feed.post',
        'record' => [
            'text' => 'Hello from atproto-php!',
            'createdAt' => date('c'),
        ],
    ],
);
```

Every request automatically:
- Attaches the `Authorization: DPoP <token>` header
- Generates a fresh DPoP proof JWT with `htm`, `htu`, `ath`, and `nonce` claims
- Handles the `use_dpop_nonce` retry if the server requires a nonce
- Refreshes the access token if it's near expiry

## Session storage

### InMemory (testing)

```php
use Gimucco\Atproto\Storage\InMemorySessionStore;
use Gimucco\Atproto\Storage\InMemoryStateStore;

$sessionStore = new InMemorySessionStore();
$stateStore = new InMemoryStateStore();
```

### File-based

```php
use Gimucco\Atproto\Storage\FileSessionStore;
use Gimucco\Atproto\Storage\FileStateStore;

$sessionStore = new FileSessionStore(
    directory: '/var/app/sessions',
    passphrase: 'your-strong-passphrase', // encrypts tokens at rest
);
$stateStore = new FileStateStore(
    directory: '/var/app/states',
    passphrase: 'your-strong-passphrase',
);
```

### PDO (MySQL, PostgreSQL, SQLite)

```php
use Gimucco\Atproto\Storage\PdoSessionStore;
use Gimucco\Atproto\Storage\PdoStateStore;
use Gimucco\Atproto\Storage\Pdo\Schema;

$pdo = new PDO('mysql:host=localhost;dbname=myapp', 'user', 'pass');

// Create tables (run once)
$sql = Schema::createTablesSql('mysql');
$pdo->exec($sql['sessions']);
$pdo->exec($sql['states']);

$sessionStore = new PdoSessionStore($pdo, passphrase: 'your-strong-passphrase');
$stateStore = new PdoStateStore($pdo, passphrase: 'your-strong-passphrase');
```

Schema supports MySQL, PostgreSQL, and SQLite:

```php
$sql = Schema::createTablesSql('mysql');   // or 'pgsql' or 'sqlite'
```

### Encryption at rest

When you provide a `passphrase`, access tokens, refresh tokens, and DPoP private keys are encrypted using `sodium_crypto_secretbox` before storage. If you don't provide one, a warning is logged but storage works in plaintext.

## Token refresh

### Automatic

When you call `$session->authenticatedRequest()`, the library checks if the access token is near expiry (within 60 seconds) and refreshes it automatically.

### Manual

```php
$session->refresh();
```

### Checking expiry

```php
if ($session->isExpired()) {
    // Token has expired
}

$expiresAt = $session->expiresAt(); // DateTimeImmutable
```

## Error handling

All exceptions extend `Gimucco\Atproto\Exception\AtprotoException`:

```php
use Gimucco\Atproto\Exception\ResolutionException;
use Gimucco\Atproto\Exception\AuthorizationException;
use Gimucco\Atproto\Exception\TokenException;
use Gimucco\Atproto\Exception\DpopException;
use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\Exception\ConfigurationException;
use Gimucco\Atproto\Exception\NetworkException;

try {
    $authUrl = $oauth->beginAuthorization($handle);
} catch (ResolutionException $e) {
    // Handle/DID/PDS could not be resolved
} catch (AuthorizationException $e) {
    // PAR request failed
} catch (NetworkException $e) {
    // HTTP transport failure
}

try {
    $session = $oauth->completeAuthorization($code, $state, $iss);
} catch (TokenException $e) {
    // Token endpoint returned an error
    echo $e->error;            // e.g., "invalid_grant"
    echo $e->errorDescription; // Human-readable message
} catch (AuthorizationException $e) {
    // State/issuer/sub mismatch
}
```

### Exception hierarchy

```
AtprotoException (base)
├── ResolutionException      — handle/DID/PDS resolution failures
├── AuthorizationException   — OAuth flow errors
│   └── TokenException       — token endpoint errors (has error, errorDescription, errorUri)
├── DpopException            — DPoP proof generation failures
├── SessionException         — storage/refresh/restore failures
├── ConfigurationException   — invalid client config
└── NetworkException         — HTTP transport failures
```

## Logging

Inject any PSR-3 logger:

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('atproto');
$logger->pushHandler(new StreamHandler('/var/log/atproto.log'));

$oauth = new OAuthClient(
    config: $config,
    sessionStore: $sessionStore,
    stateStore: $stateStore,
    httpClient: $httpClient,
    requestFactory: $factory,
    streamFactory: $factory,
    logger: $logger,
);
```

The library logs:
- **Debug:** DPoP nonce retries
- **Warning:** Unencrypted storage backends
- **Error:** Failed token refreshes

## Security

The library applies several protections by default: SSRF blocking on outbound requests, sub-claim and issuer validation on the OAuth callback, and optional libsodium encryption of tokens and DPoP keys at rest.

See [SECURITY.md](SECURITY.md) for the full security model, threat model, vulnerability reporting, and guidance on storing the client private key, choosing an encryption passphrase, and the SSRF guard's TOCTOU window.

## Troubleshooting

### "use_dpop_nonce" errors

This is normal. The AT Protocol requires DPoP nonces, and the first request to any server will fail with `use_dpop_nonce`. The library retries automatically. If you see this in logs, it's working correctly.

### `client_id` URL must match exactly

The URL in your `ClientConfig::clientId` must match the URL where you host the client metadata document **exactly** — same scheme, host, path, and no trailing slash differences.

### Clock skew on DPoP `iat`

DPoP proofs include an `iat` (issued-at) timestamp. If your server clock is off by more than a few seconds, the authorization server may reject them. Use NTP to keep your clock synced.

### "Sub mismatch" error

After token exchange, the library verifies the `sub` claim in the token response matches the DID resolved during `beginAuthorization()`. If they don't match, this is a security check failure — the authorization server returned tokens for a different user than expected.

### SSL certificate issues in development

If you're testing locally, you may need to configure your HTTP client to accept self-signed certificates. With Guzzle:

```php
$httpClient = new \GuzzleHttp\Client(['verify' => false]);
```

**Never do this in production.**

## Testing your integration

See the [examples/](examples/) directory for a complete working example you can run locally:

```bash
cd examples
cp config.example.php config.php
# Edit config.php with your settings
php -S localhost:8080 -t public
```

## Roadmap

Planned for future releases (not yet implemented):

- **Token revocation** (RFC 7009) — explicit `revokeSession()` calls currently delete local state but don't notify the authorization server. A revocation endpoint call will be added when the AT Protocol spec finalizes the contract.
- **Bidirectional handle verification** — after resolving handle → DID, fetch the DID document and confirm the `alsoKnownAs` field lists the original handle. Today the library trusts the handle-to-DID mapping; bidirectional verification protects against handle squatting if a DNS or `.well-known` record is compromised.
- **Rate limiting / exponential backoff on nonce retry** — the `use_dpop_nonce` retry currently fires once. Pathological servers that loop through nonces without converging would cause repeated requests; a configurable retry budget will be added.
- **`did:plc` directory fallback URLs** — currently uses `https://plc.directory` only. Future versions will accept a list of mirror directories and try them in order.
- **Optional DNS pinning** in the SSRF guard for transports that support it (e.g., Guzzle with `CURLOPT_RESOLVE`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and submission guidelines.

## License

This project is licensed under GPL-2.0-or-later. See [LICENSE](LICENSE) for the full text.

### Attribution

Portions of this library are adapted from [Automattic/wordpress-atmosphere](https://github.com/Automattic/wordpress-atmosphere), licensed under GPL-2.0-or-later. Original copyright Automattic Inc.

## Acknowledgments

- [Automattic](https://automattic.com/) and the [ATmosphere](https://github.com/Automattic/wordpress-atmosphere) team for the reference PHP implementation
- The [Bluesky](https://bsky.app/) team for the AT Protocol and its OAuth profile
- RFC authors: RFC 9449 (DPoP), RFC 9126 (PAR), RFC 7636 (PKCE)
