<?php

/**
 * Authenticated request example — restores a session and calls
 * com.atproto.server.getSession on the user's PDS.
 */

declare(strict_types=1);

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\OAuthClient;
use Gimucco\Atproto\Storage\FileSessionStore;
use Gimucco\Atproto\Storage\FileStateStore;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;

require __DIR__.'/../vendor/autoload.php';

$configPath = __DIR__.'/config.php';
if (!file_exists($configPath)) {
	http_response_code(500);
	echo 'Missing config.php — copy config.example.php to config.php and edit it.';
	exit(1);
}

/** @var array<string, string> $config */
$config = require $configPath;

$did = $_GET['did'] ?? '';
if ($did === '') {
	http_response_code(400);
	echo 'Missing "did" query parameter. Sign in first via <a href="public/login.php">login</a>.';
	exit(1);
}

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

	$storageDir = $config['storage_dir'] ?? __DIR__.'/storage';
	$passphrase = $config['encryption_passphrase'] ?? null;

	$httpClient = new GuzzleClient(['timeout' => 30]);
	$httpFactory = new HttpFactory();

	$oauthClient = new OAuthClient(
		config: $clientConfig,
		sessionStore: new FileSessionStore($storageDir.'/sessions', $passphrase),
		stateStore: new FileStateStore($storageDir.'/states', $passphrase),
		httpClient: $httpClient,
		requestFactory: $httpFactory,
		streamFactory: $httpFactory,
	);

	$session = $oauthClient->restoreSession($did);
	if ($session === null) {
		http_response_code(404);
		echo 'No session found for this DID. <a href="public/login.php">Sign in first</a>.';
		exit(1);
	}

	// Call com.atproto.server.getSession on the user's PDS
	$response = $session->authenticatedRequest(
		method: 'GET',
		url: rtrim($session->pdsUrl, '/').'/xrpc/com.atproto.server.getSession',
	);

	$statusCode = $response->getStatusCode();
	$body = (string) $response->getBody();

	/** @var array<string, mixed>|null $data */
	$data = json_decode($body, true);
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Authenticated Request</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; }
			pre { background: #f5f5f5; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 0.9em; }
			code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
			a { color: #0085ff; }
			.label { font-weight: 600; margin-top: 16px; }
		</style>
	</head>
	<body>
		<h1>Authenticated Request Result</h1>
		<p class="label">Endpoint</p>
		<p><code>GET <?= htmlspecialchars(rtrim($session->pdsUrl, '/').'/xrpc/com.atproto.server.getSession', ENT_QUOTES, 'UTF-8') ?></code></p>
		<p class="label">HTTP Status: <?= $statusCode ?></p>
		<p class="label">Response</p>
		<pre><?= htmlspecialchars(json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8') ?></pre>
		<p><a href="public/login.php">Sign in as another user</a></p>
	</body>
	</html>
	<?php
} catch (Throwable $e) {
	http_response_code(500);
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Request Error</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 80px auto; padding: 0 20px; }
			.error { color: #c00; }
			a { color: #0085ff; }
		</style>
	</head>
	<body>
		<h1>Request Error</h1>
		<p class="error"><?= htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') ?></p>
		<p><a href="public/login.php">Sign in again</a></p>
	</body>
	</html>
	<?php
	exit(1);
}
