<?php

/**
 * Manual end-to-end test against a live PDS (e.g., bsky.social).
 *
 * Usage:
 *   1. Generate a keypair: openssl ecparam -genkey -name prime256v1 -noout -out private.pem
 *   2. Set up client metadata and JWKS hosting (see examples/)
 *   3. Run: php tests/manual/live-test.php <handle>
 *
 * This script tests handle resolution and DID resolution only (non-destructive).
 * It does NOT perform a full OAuth flow (that requires browser interaction).
 */

declare(strict_types=1);

use Gimucco\Atproto\Internal\Resolver\AuthServerResolver;
use Gimucco\Atproto\Internal\Resolver\DidResolver;
use Gimucco\Atproto\Internal\Resolver\HandleResolver;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;

require __DIR__.'/../../vendor/autoload.php';

$handle = $argv[1] ?? null;

if ($handle === null) {
	echo "Usage: php tests/manual/live-test.php <handle>\n";
	echo "Example: php tests/manual/live-test.php alice.bsky.social\n";
	exit(1);
}

$httpClient = new Client(['timeout' => 10]);
$factory = new HttpFactory();

echo "--- AT Protocol Resolution Test ---\n\n";

// Step 1: Resolve handle to DID
echo "1. Resolving handle: {$handle}\n";
$handleResolver = new HandleResolver($httpClient, $factory);
try {
	$did = $handleResolver->resolve($handle);
	echo "   DID: {$did}\n\n";
} catch (\Throwable $e) {
	echo "   FAILED: {$e->getMessage()}\n";
	exit(1);
}

// Step 2: Resolve DID to PDS
echo "2. Resolving DID document...\n";
$didResolver = new DidResolver($httpClient, $factory);
try {
	$identity = $didResolver->resolve($did);
	echo "   PDS: {$identity['pds']}\n";
	echo '   Handle (from DID doc): '.($identity['handle'] ?? 'N/A')."\n\n";
} catch (\Throwable $e) {
	echo "   FAILED: {$e->getMessage()}\n";
	exit(1);
}

// Step 3: Discover auth server
echo "3. Discovering authorization server...\n";
$authServerResolver = new AuthServerResolver($httpClient, $factory);
try {
	$authServer = $authServerResolver->resolve($identity['pds']);
	echo "   Issuer: {$authServer['issuer_url']}\n";
	echo "   Auth endpoint: {$authServer['authorization_endpoint']}\n";
	echo "   Token endpoint: {$authServer['token_endpoint']}\n";
	echo "   PAR endpoint: {$authServer['pushed_authorization_request_endpoint']}\n\n";
} catch (\Throwable $e) {
	echo "   FAILED: {$e->getMessage()}\n";
	exit(1);
}

echo "--- All resolution steps passed ---\n";
