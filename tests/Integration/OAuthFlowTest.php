<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Integration;

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\Exception\AuthorizationException;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use Gimucco\Atproto\OAuthClient;
use Gimucco\Atproto\Storage\InMemorySessionStore;
use Gimucco\Atproto\Storage\InMemoryStateStore;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests that exercise the full OAuth 2.1 flow against a
 * mocked HTTP layer. No real network calls are made.
 */
final class OAuthFlowTest extends TestCase
{
	private static string $clientPrivateKeyPem;

	public static function setUpBeforeClass(): void
	{
		self::$clientPrivateKeyPem = KeyManager::generateDpopKeyPem();
	}

	// ------------------------------------------------------------------
	// 1. Full authorization flow (beginAuthorization)
	// ------------------------------------------------------------------

	public function testFullAuthorizationFlow(): void
	{
		$mock = new MockHttpClient();
		$httpFactory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();
		$stateStore = new InMemoryStateStore();

		// 1. Handle resolution
		$mock->addResponse(new Response(200, [], 'did:plc:testuser123'));

		// 2. DID document
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'id' => 'did:plc:testuser123',
			'alsoKnownAs' => ['at://alice.test'],
			'service' => [[
				'id' => '#atproto_pds',
				'type' => 'AtprotoPersonalDataServer',
				'serviceEndpoint' => 'https://pds.test.com',
			]],
		], JSON_THROW_ON_ERROR)));

		// 3. Protected resource metadata
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'authorization_servers' => ['https://auth.test.com'],
		], JSON_THROW_ON_ERROR)));

		// 4. Auth server metadata
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'issuer' => 'https://auth.test.com',
			'authorization_endpoint' => 'https://auth.test.com/authorize',
			'token_endpoint' => 'https://auth.test.com/token',
			'pushed_authorization_request_endpoint' => 'https://auth.test.com/par',
		], JSON_THROW_ON_ERROR)));

		// 5. PAR request #1 -- DPoP nonce error
		$mock->addResponse(new Response(400, [
			'Content-Type' => 'application/json',
			'DPoP-Nonce' => 'test-nonce-1',
		], json_encode([
			'error' => 'use_dpop_nonce',
		], JSON_THROW_ON_ERROR)));

		// 6. PAR request #2 -- success (retry with nonce)
		$mock->addResponse(new Response(201, ['Content-Type' => 'application/json'], json_encode([
			'request_uri' => 'urn:ietf:params:oauth:request_uri:test123',
		], JSON_THROW_ON_ERROR)));

		$client = new OAuthClient(
			config: $this->createClientConfig(),
			sessionStore: $sessionStore,
			stateStore: $stateStore,
			httpClient: $mock,
			requestFactory: $httpFactory,
			streamFactory: $httpFactory,
			ssrfProtection: false,
		);

		$url = $client->beginAuthorization('alice.test');

		// The returned URL must point to the authorization endpoint
		self::assertStringStartsWith('https://auth.test.com/authorize?', $url);

		// It must contain the PAR request_uri
		self::assertStringContainsString(
			urlencode('urn:ietf:params:oauth:request_uri:test123'),
			$url,
		);

		// It must contain the client_id
		self::assertStringContainsString(
			urlencode('https://app.test.com/client-metadata'),
			$url,
		);

		// Verify all 6 HTTP requests were sent
		self::assertCount(6, $mock->sentRequests);

		// Verify request URLs in order
		self::assertSame('https://alice.test/.well-known/atproto-did', (string) $mock->sentRequests[0]->getUri());
		self::assertSame('https://plc.directory/did:plc:testuser123', (string) $mock->sentRequests[1]->getUri());
		self::assertSame('https://pds.test.com/.well-known/oauth-protected-resource', (string) $mock->sentRequests[2]->getUri());
		self::assertSame('https://auth.test.com/.well-known/oauth-authorization-server', (string) $mock->sentRequests[3]->getUri());
		self::assertSame('https://auth.test.com/par', (string) $mock->sentRequests[4]->getUri());
		self::assertSame('https://auth.test.com/par', (string) $mock->sentRequests[5]->getUri());

		// First four should be GET, last two POST
		self::assertSame('GET', $mock->sentRequests[0]->getMethod());
		self::assertSame('GET', $mock->sentRequests[1]->getMethod());
		self::assertSame('GET', $mock->sentRequests[2]->getMethod());
		self::assertSame('GET', $mock->sentRequests[3]->getMethod());
		self::assertSame('POST', $mock->sentRequests[4]->getMethod());
		self::assertSame('POST', $mock->sentRequests[5]->getMethod());
	}

	// ------------------------------------------------------------------
	// 1b. Server-first authorization (no handle, redirect straight to auth server)
	// ------------------------------------------------------------------

	public function testServerFirstAuthorizationFlow(): void
	{
		$mock = new MockHttpClient();
		$httpFactory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();
		$stateStore = new InMemoryStateStore();

		// Direct fetch of auth server metadata -- no handle/DID/PDS resolution
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'issuer' => 'https://auth.test.com',
			'authorization_endpoint' => 'https://auth.test.com/authorize',
			'token_endpoint' => 'https://auth.test.com/token',
			'pushed_authorization_request_endpoint' => 'https://auth.test.com/par',
		], JSON_THROW_ON_ERROR)));

		// PAR success on first try (no nonce dance for this test)
		$mock->addResponse(new Response(201, ['Content-Type' => 'application/json'], json_encode([
			'request_uri' => 'urn:ietf:params:oauth:request_uri:server-first',
		], JSON_THROW_ON_ERROR)));

		$client = new OAuthClient(
			config: $this->createClientConfig(),
			sessionStore: $sessionStore,
			stateStore: $stateStore,
			httpClient: $mock,
			requestFactory: $httpFactory,
			streamFactory: $httpFactory,
			ssrfProtection: false,
		);

		$url = $client->beginAuthorization(
			handleOrDid: null,
			authorizationServer: 'https://auth.test.com',
		);

		self::assertStringStartsWith('https://auth.test.com/authorize?', $url);
		self::assertStringContainsString(
			urlencode('urn:ietf:params:oauth:request_uri:server-first'),
			$url,
		);

		// Only 2 HTTP requests: auth server metadata, PAR
		self::assertCount(2, $mock->sentRequests);
		self::assertSame('https://auth.test.com/.well-known/oauth-authorization-server', (string) $mock->sentRequests[0]->getUri());
		self::assertSame('https://auth.test.com/par', (string) $mock->sentRequests[1]->getUri());

		// Verify the PAR body did NOT include login_hint
		$parBody = (string) $mock->sentRequests[1]->getBody();
		self::assertStringNotContainsString('login_hint', $parBody);
	}

	// ------------------------------------------------------------------
	// 2. Complete authorization (token exchange)
	// ------------------------------------------------------------------

	public function testCompleteAuthorization(): void
	{
		$mock = new MockHttpClient();
		$httpFactory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();
		$stateStore = new InMemoryStateStore();

		$dpopKeyPem = KeyManager::generateDpopKeyPem();

		// Pre-populate state store with authorization data
		$stateStore->save('test-state', [
			'did' => 'did:plc:testuser123',
			'handle' => 'alice.test',
			'pds_url' => 'https://pds.test.com',
			'auth_server' => [
				'issuer_url' => 'https://auth.test.com',
				'token_endpoint' => 'https://auth.test.com/token',
				'authorization_endpoint' => 'https://auth.test.com/authorize',
			],
			'code_verifier' => 'test-verifier-value',
			'dpop_key_pem' => $dpopKeyPem,
		], 600);

		// 1. Token exchange #1 -- DPoP nonce error
		$mock->addResponse(new Response(400, [
			'Content-Type' => 'application/json',
			'DPoP-Nonce' => 'token-nonce-1',
		], json_encode([
			'error' => 'use_dpop_nonce',
		], JSON_THROW_ON_ERROR)));

		// 2. Token exchange #2 -- success
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'access_token' => 'test-access-token',
			'refresh_token' => 'test-refresh-token',
			'token_type' => 'DPoP',
			'expires_in' => 300,
			'scope' => 'atproto transition:generic',
			'sub' => 'did:plc:testuser123',
		], JSON_THROW_ON_ERROR)));

		$client = new OAuthClient(
			config: $this->createClientConfig(),
			sessionStore: $sessionStore,
			stateStore: $stateStore,
			httpClient: $mock,
			requestFactory: $httpFactory,
			streamFactory: $httpFactory,
			ssrfProtection: false,
		);

		$session = $client->completeAuthorization('auth-code', 'test-state', 'https://auth.test.com');

		// Verify session properties
		self::assertSame('did:plc:testuser123', $session->did);
		self::assertSame('alice.test', $session->handle);
		self::assertSame('test-access-token', $session->accessToken());
		self::assertSame('atproto transition:generic', $session->scope());
		self::assertFalse($session->isExpired());

		// Both token requests should target the token endpoint
		self::assertCount(2, $mock->sentRequests);
		self::assertSame('https://auth.test.com/token', (string) $mock->sentRequests[0]->getUri());
		self::assertSame('https://auth.test.com/token', (string) $mock->sentRequests[1]->getUri());

		// State should be consumed (deleted) after completion
		self::assertNull($stateStore->get('test-state'));

		// Session should be persisted in the session store
		$stored = $sessionStore->findByDid('did:plc:testuser123');
		self::assertNotNull($stored);
		self::assertSame('test-access-token', $stored->accessToken);
	}

	// ------------------------------------------------------------------
	// 3. Sub mismatch throws
	// ------------------------------------------------------------------

	public function testSubMismatchThrows(): void
	{
		$mock = new MockHttpClient();
		$httpFactory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();
		$stateStore = new InMemoryStateStore();

		$dpopKeyPem = KeyManager::generateDpopKeyPem();

		$stateStore->save('test-state', [
			'did' => 'did:plc:testuser123',
			'handle' => 'alice.test',
			'pds_url' => 'https://pds.test.com',
			'auth_server' => [
				'issuer_url' => 'https://auth.test.com',
				'token_endpoint' => 'https://auth.test.com/token',
				'authorization_endpoint' => 'https://auth.test.com/authorize',
			],
			'code_verifier' => 'test-verifier-value',
			'dpop_key_pem' => $dpopKeyPem,
		], 600);

		// 1. Token exchange #1 -- DPoP nonce error
		$mock->addResponse(new Response(400, [
			'Content-Type' => 'application/json',
			'DPoP-Nonce' => 'token-nonce-1',
		], json_encode([
			'error' => 'use_dpop_nonce',
		], JSON_THROW_ON_ERROR)));

		// 2. Token exchange #2 -- success but wrong sub
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'access_token' => 'test-access-token',
			'refresh_token' => 'test-refresh-token',
			'token_type' => 'DPoP',
			'expires_in' => 300,
			'scope' => 'atproto transition:generic',
			'sub' => 'did:plc:wronguser',
		], JSON_THROW_ON_ERROR)));

		$client = new OAuthClient(
			config: $this->createClientConfig(),
			sessionStore: $sessionStore,
			stateStore: $stateStore,
			httpClient: $mock,
			requestFactory: $httpFactory,
			streamFactory: $httpFactory,
			ssrfProtection: false,
		);

		$this->expectException(AuthorizationException::class);
		$this->expectExceptionMessageMatches('/[Ss]ub mismatch/');

		$client->completeAuthorization('auth-code', 'test-state', 'https://auth.test.com');
	}

	// ------------------------------------------------------------------
	// 4. Invalid state throws
	// ------------------------------------------------------------------

	public function testInvalidStateThrows(): void
	{
		$mock = new MockHttpClient();
		$httpFactory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();
		$stateStore = new InMemoryStateStore();

		$client = new OAuthClient(
			config: $this->createClientConfig(),
			sessionStore: $sessionStore,
			stateStore: $stateStore,
			httpClient: $mock,
			requestFactory: $httpFactory,
			streamFactory: $httpFactory,
			ssrfProtection: false,
		);

		$this->expectException(AuthorizationException::class);
		$this->expectExceptionMessageMatches('/[Ii]nvalid|[Ee]xpired/');

		$client->completeAuthorization('auth-code', 'nonexistent-state', 'https://auth.test.com');
	}

	// ------------------------------------------------------------------
	// 5. Issuer mismatch throws
	// ------------------------------------------------------------------

	public function testIssuerMismatchThrows(): void
	{
		$mock = new MockHttpClient();
		$httpFactory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();
		$stateStore = new InMemoryStateStore();

		$dpopKeyPem = KeyManager::generateDpopKeyPem();

		$stateStore->save('test-state', [
			'did' => 'did:plc:testuser123',
			'handle' => 'alice.test',
			'pds_url' => 'https://pds.test.com',
			'auth_server' => [
				'issuer_url' => 'https://auth.test.com',
				'token_endpoint' => 'https://auth.test.com/token',
				'authorization_endpoint' => 'https://auth.test.com/authorize',
			],
			'code_verifier' => 'test-verifier-value',
			'dpop_key_pem' => $dpopKeyPem,
		], 600);

		$client = new OAuthClient(
			config: $this->createClientConfig(),
			sessionStore: $sessionStore,
			stateStore: $stateStore,
			httpClient: $mock,
			requestFactory: $httpFactory,
			streamFactory: $httpFactory,
			ssrfProtection: false,
		);

		$this->expectException(AuthorizationException::class);
		$this->expectExceptionMessageMatches('/[Ii]ssuer mismatch/');

		$client->completeAuthorization('auth-code', 'test-state', 'https://evil.com');
	}

	// ------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------

	private function createClientConfig(): ClientConfig
	{
		return new ClientConfig(
			clientId: 'https://app.test.com/client-metadata',
			redirectUri: 'https://app.test.com/callback',
			scope: 'atproto transition:generic',
			clientName: 'Test App',
			privateKey: self::$clientPrivateKeyPem,
		);
	}
}
