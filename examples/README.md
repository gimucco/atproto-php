# Examples

A complete working demo of the AT Protocol OAuth 2.1 flow using this library.

## Prerequisites

- PHP 8.2+ with extensions: `json`, `curl`, `openssl`, `sodium`
- [Composer](https://getcomposer.org/) installed
- A domain with HTTPS (the AT Protocol requires `https://` for client metadata and callbacks)

## Setup

### 1. Install dependencies

From the repository root:

```bash
composer install
```

### 2. Generate an ES256 private key

```bash
openssl ecparam -name prime256v1 -genkey -noout -out examples/private.pem
```

Keep this file safe and never commit it.

### 3. Configure

```bash
cp examples/config.example.php examples/config.php
```

Edit `examples/config.php` and set:

- **`client_id`** — The HTTPS URL where your client metadata will be served (e.g., `https://your-domain.com/client-metadata.json`)
- **`redirect_uri`** — Your OAuth callback URL (e.g., `https://your-domain.com/callback`)
- **`client_name`** — A human-readable name for your app
- **`client_uri`** — Your app's homepage URL
- **`jwks_uri`** — The HTTPS URL where your JWKS will be served (e.g., `https://your-domain.com/jwks.json`)
- **`private_key_path`** — Path to the ES256 private key generated above
- **`encryption_passphrase`** — A strong random passphrase for encrypting tokens at rest

### 4. Generate static metadata files

The OAuth client metadata and JWKS are static documents derived from your config and key. Generate them once with the bundled CLI tool:

```bash
bin/generate-metadata --config=examples/config.php --output=examples/public
```

This writes two files:

- `examples/public/client-metadata.json` — OAuth client metadata
- `examples/public/jwks.json` — Public key in JWKS format

Re-run this command whenever you change your config or rotate your key.

> The generated files are listed in `.gitignore` because they're derived from your private config — never commit them.

If you've installed this library as a Composer dependency in another project, the same script is available as `vendor/bin/generate-metadata`.

### 5. Host the metadata endpoints

The AT Protocol authorization server fetches your client metadata and JWKS during the OAuth flow. These must be publicly accessible at the URLs you set in `config.php`.

If you're using a web server (Apache, Nginx), simply point it at `examples/public/` — the static `.json` files will be served as-is, no PHP involved.

### 6. Run the development server

For local testing you can use PHP's built-in server (note: the AT Protocol still requires your `client_id` and callback to be reachable over HTTPS, so you'll need a tunnel or reverse proxy for a real flow):

```bash
php -S localhost:8080 -t examples/public
```

Then visit `http://localhost:8080/login.php` in your browser.

The built-in server serves the generated `.json` files as static content automatically — only `.php` URLs are routed through PHP.

## Files

| File | Purpose |
|------|---------|
| `config.example.php` | Configuration template — copy to `config.php` |
| `public/login.php` | Login form and authorization start |
| `public/callback.php` | OAuth callback — exchanges code for tokens |
| `authenticated-request.php` | Restores a session and makes an API call |
| `public/client-metadata.json` | *(generated)* OAuth client metadata |
| `public/jwks.json` | *(generated)* Public key set |

## Flow

1. Run `bin/generate-metadata` once to produce the static metadata files
2. User visits `login.php` and enters their Bluesky handle
3. The library resolves the handle, discovers the authorization server, and redirects the user
4. The user approves the app on the authorization server
5. The authorization server fetches your `client-metadata.json` and `jwks.json` (static files served by your web server)
6. The authorization server redirects back to `callback.php` with an authorization code
7. The library exchanges the code for tokens and stores the session
8. `authenticated-request.php` restores the session and calls `com.atproto.server.getSession`
