<?php

/**
 * Login page — begins the AT Protocol OAuth 2.1 authorization flow.
 *
 * Displays a form to enter a Bluesky handle, then resolves the user's identity
 * and redirects to the authorization server.
 */

declare(strict_types=1);

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\OAuthClient;
use Gimucco\Atproto\Storage\FileSessionStore;
use Gimucco\Atproto\Storage\FileStateStore;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;

require __DIR__.'/../../vendor/autoload.php';

$configPath = __DIR__.'/../config.php';
if (!file_exists($configPath)) {
	http_response_code(500);
	echo 'Missing config.php — copy config.example.php to config.php and edit it.';
	exit(1);
}

/** @var array<string, string> $config */
$config = require $configPath;

// Show login form on GET requests; POST starts the OAuth flow
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>AT Protocol OAuth Login</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; }
			h1 { font-size: 1.4em; }
			form { margin-top: 24px; }
			label { display: block; margin-bottom: 6px; font-weight: 600; }
			input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 1em; box-sizing: border-box; }
			button { margin-top: 12px; padding: 10px 24px; background: #0085ff; color: #fff; border: none; border-radius: 6px; font-size: 1em; cursor: pointer; width: 100%; }
			button:hover { background: #0070e0; }
			.secondary { background: #fff; color: #0085ff; border: 1px solid #0085ff; }
			.secondary:hover { background: #f3f8ff; }
			.divider { text-align: center; color: #888; margin: 20px 0; font-size: 0.9em; }
			.hint { font-size: 0.85em; color: #666; margin-top: 6px; }
			.error { color: #c00; margin-top: 12px; }
		</style>
	</head>
	<body>
		<h1>Sign in with AT Protocol</h1>

		<form method="post" action="">
			<button type="submit">Sign in with Bluesky</button>
			<p class="hint">You'll choose your account on the next page.</p>
		</form>

		<div class="divider">— or —</div>

		<form method="post" action="">
			<label for="handle">Your handle (optional)</label>
			<input type="text" id="handle" name="handle" placeholder="alice.bsky.social">
			<button type="submit" class="secondary">Sign in with handle</button>
			<p class="hint">Pre-fills your identifier on the next page.</p>
		</form>
	</body>
	</html>
	<?php
	exit;
}

$handle = isset($_POST['handle']) ? trim($_POST['handle']) : '';

try {
	$privateKey = file_get_contents($config['private_key_path']);
	if ($privateKey === false) {
		throw new RuntimeException('Cannot read private key at: '.$config['private_key_path']);
	}

	$clientConfig = new ClientConfig(
		clientId: $config['client_id'],
		redirectUri: $config['redirect_uri'],
		scope: $config['scope'],
		clientName: $config['client_name'],
		clientUri: $config['client_uri'] ?? null,
		jwksUri: $config['jwks_uri'] ?? null,
		privateKey: $privateKey,
		encryptionPassphrase: $config['encryption_passphrase'] ?? null,
	);

	$storageDir = $config['storage_dir'] ?? __DIR__.'/../storage';
	$passphrase = $config['encryption_passphrase'] ?? null;

	$httpClient = new GuzzleClient(['timeout' => 30]);
	$httpFactory = new HttpFactory();

	$logger = new class extends \Psr\Log\AbstractLogger {
		public function log($level, $message, array $context = []): void
		{
			error_log("[{$level}] atproto: {$message} ".json_encode($context));
		}
	};
	$oauthClient = new OAuthClient(
		config: $clientConfig,
		sessionStore: new FileSessionStore($storageDir.'/sessions', $passphrase),
		stateStore: new FileStateStore($storageDir.'/states', $passphrase),
		httpClient: $httpClient,
		requestFactory: $httpFactory,
		streamFactory: $httpFactory,
		logger: $logger,
	);

	// Empty handle → server-first flow: redirect straight to the auth server
	// and let the user enter their identifier there.
	$authUrl = $oauthClient->beginAuthorization($handle !== '' ? $handle : null);
	header('Location: '.$authUrl);
	exit;
} catch (Throwable $e) {
	http_response_code(500);
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Login Error</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; }
			.error { color: #c00; }
			a { color: #0085ff; }
		</style>
	</head>
	<body>
		<h1>Login Error</h1>
		<p class="error"><?= htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') ?></p>
		<p><a href="login.php">Try again</a></p>
	</body>
	</html>
	<?php
	exit(1);
}
