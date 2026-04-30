<?php

/**
 * OAuth callback — completes the authorization flow after the user approves.
 *
 * Exchanges the authorization code for tokens, validates the response,
 * and stores the session.
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

$code = $_GET['code'] ?? '';
$state = $_GET['state'] ?? '';
$iss = $_GET['iss'] ?? '';
$error = $_GET['error'] ?? '';

if ($error !== '') {
	$errorDescription = $_GET['error_description'] ?? 'Unknown error';
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Authorization Denied</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 80px auto; padding: 0 20px; }
			.error { color: #c00; }
			a { color: #0085ff; }
		</style>
	</head>
	<body>
		<h1>Authorization Denied</h1>
		<p class="error"><?= htmlspecialchars($error.': '.$errorDescription, ENT_QUOTES, 'UTF-8') ?></p>
		<p><a href="login.php">Try again</a></p>
	</body>
	</html>
	<?php
	exit;
}

if ($code === '' || $state === '' || $iss === '') {
	http_response_code(400);
	echo 'Missing required callback parameters (code, state, iss).';
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

	$session = $oauthClient->completeAuthorization($code, $state, $iss);
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Authorization Successful</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 80px auto; padding: 0 20px; }
			.success { color: #080; }
			code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
			a { color: #0085ff; }
		</style>
	</head>
	<body>
		<h1 class="success">Authorization Successful</h1>
		<p>Signed in as <strong><?= htmlspecialchars($session->handle, ENT_QUOTES, 'UTF-8') ?></strong></p>
		<p>DID: <code><?= htmlspecialchars($session->did, ENT_QUOTES, 'UTF-8') ?></code></p>
		<p><a href="../authenticated-request.php?did=<?= urlencode($session->did) ?>">Make an authenticated request</a></p>
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
		<title>Authorization Error</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 80px auto; padding: 0 20px; }
			.error { color: #c00; }
			a { color: #0085ff; }
		</style>
	</head>
	<body>
		<h1>Authorization Error</h1>
		<p class="error"><?= htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') ?></p>
		<p><a href="login.php">Try again</a></p>
	</body>
	</html>
	<?php
	exit(1);
}
