<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit;

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use Gimucco\Atproto\OAuthClient;
use Gimucco\Atproto\Session;
use Gimucco\Atproto\Storage\InMemorySessionStore;
use Gimucco\Atproto\Storage\InMemoryStateStore;
use Gimucco\Atproto\StoredSession;
use Gimucco\Atproto\Tests\Integration\MockHttpClient;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class SessionTest extends TestCase
{
	private static string $clientPem;
	private static string $dpopPem;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__.'/../Integration/MockHttpClient.php';
		self::$clientPem = KeyManager::generateDpopKeyPem();
		self::$dpopPem = KeyManager::generateDpopKeyPem();
	}

	// ──────────────────────────────────────────────────────────
	// authenticatedRawRequest()
	// ──────────────────────────────────────────────────────────

	public function testAuthenticatedRawRequestSendsBodyVerbatim(): void
	{
		$binary = "\x89PNG\r\n\x1a\n".random_bytes(64);   // PNG header + payload
		[$session, $mock] = $this->makeSession();

		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'blob' => ['$type' => 'blob', 'ref' => ['$link' => 'bafkreitest'], 'mimeType' => 'image/png', 'size' => \strlen($binary)],
		], JSON_THROW_ON_ERROR)));

		$response = $session->authenticatedRawRequest(
			'POST',
			'https://pds.test.com/xrpc/com.atproto.repo.uploadBlob',
			$binary,
			'image/png',
		);

		self::assertSame(200, $response->getStatusCode());
		self::assertCount(1, $mock->sentRequests);

		$sent = $mock->sentRequests[0];
		self::assertSame('POST', $sent->getMethod());
		self::assertSame('image/png', $sent->getHeaderLine('Content-Type'));
		self::assertSame($binary, (string) $sent->getBody(), 'binary body must pass through unmodified');
	}

	public function testAuthenticatedRawRequestAttachesDpopAndAuthorizationHeaders(): void
	{
		[$session, $mock] = $this->makeSession();

		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], '{}'));

		$session->authenticatedRawRequest(
			'POST',
			'https://pds.test.com/xrpc/com.atproto.repo.uploadBlob',
			'raw bytes',
			'application/octet-stream',
		);

		$sent = $mock->sentRequests[0];
		self::assertSame('DPoP test-access-token', $sent->getHeaderLine('Authorization'));
		self::assertNotEmpty($sent->getHeaderLine('DPoP'));

		// DPoP JWT should have three parts and decode to a sane payload.
		$parts = explode('.', $sent->getHeaderLine('DPoP'));
		self::assertCount(3, $parts);
		$payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);
		self::assertSame('POST', $payload['htm']);
		self::assertSame('https://pds.test.com/xrpc/com.atproto.repo.uploadBlob', $payload['htu']);
		self::assertArrayHasKey('ath', $payload, 'resource DPoP must include ath claim');
	}

	public function testAuthenticatedRawRequestRetriesOnUseDpopNonce(): void
	{
		[$session, $mock] = $this->makeSession();

		// First response: 401 with WWW-Authenticate use_dpop_nonce + DPoP-Nonce header
		$mock->addResponse(new Response(401, [
			'WWW-Authenticate' => 'DPoP error="use_dpop_nonce", error_description="..."',
			'DPoP-Nonce' => 'pds-nonce-1',
		], '{"error":"use_dpop_nonce"}'));

		// Retry: success
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], '{"ok":true}'));

		$response = $session->authenticatedRawRequest(
			'POST',
			'https://pds.test.com/xrpc/com.atproto.repo.uploadBlob',
			'payload',
			'application/octet-stream',
		);

		self::assertSame(200, $response->getStatusCode());
		self::assertCount(2, $mock->sentRequests, 'expected initial + retry request');

		// Initial DPoP must NOT have a nonce
		$first = json_decode((string) base64_decode(strtr(explode('.', $mock->sentRequests[0]->getHeaderLine('DPoP'))[1], '-_', '+/'), true), true);
		self::assertArrayNotHasKey('nonce', $first);

		// Retry DPoP MUST have the server's nonce
		$retry = json_decode((string) base64_decode(strtr(explode('.', $mock->sentRequests[1]->getHeaderLine('DPoP'))[1], '-_', '+/'), true), true);
		self::assertSame('pds-nonce-1', $retry['nonce']);

		// Body must still be the same on retry
		self::assertSame('payload', (string) $mock->sentRequests[1]->getBody());
	}

	public function testAuthenticatedRawRequestRefreshesNearExpiryToken(): void
	{
		// Build a session with an access token expiring NOW (well within the 60s buffer)
		[$session, $mock] = $this->makeSession(expiresAt: new \DateTimeImmutable());

		// First response on the wire: token-refresh success (refreshSession goes through same mock)
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'access_token' => 'rotated-access-token',
			'refresh_token' => 'rotated-refresh-token',
			'expires_in' => 3600,
		], JSON_THROW_ON_ERROR)));

		// Second response: the actual blob upload
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], '{"blob":{}}'));

		$response = $session->authenticatedRawRequest(
			'POST',
			'https://pds.test.com/xrpc/com.atproto.repo.uploadBlob',
			'bytes',
			'image/jpeg',
		);

		self::assertSame(200, $response->getStatusCode());
		self::assertCount(2, $mock->sentRequests);

		// Sequence: token endpoint (refresh) then the resource request
		self::assertSame('https://auth.test.com/token', (string) $mock->sentRequests[0]->getUri());
		self::assertSame('https://pds.test.com/xrpc/com.atproto.repo.uploadBlob', (string) $mock->sentRequests[1]->getUri());

		// The resource request must use the rotated token
		self::assertSame('DPoP rotated-access-token', $mock->sentRequests[1]->getHeaderLine('Authorization'));
	}

	public function testCallerSuppliedContentTypeWinsOverArgument(): void
	{
		[$session, $mock] = $this->makeSession();
		$mock->addResponse(new Response(200, [], ''));

		$session->authenticatedRawRequest(
			method: 'POST',
			url: 'https://pds.test.com/xrpc/com.atproto.repo.uploadBlob',
			body: 'x',
			contentType: 'image/png',                          // would normally win
			headers: ['Content-Type' => 'application/cbor'],   // caller override
		);

		self::assertSame('application/cbor', $mock->sentRequests[0]->getHeaderLine('Content-Type'));
	}

	public function testCallerHeaderOverrideIsCaseInsensitive(): void
	{
		[$session, $mock] = $this->makeSession();
		$mock->addResponse(new Response(200, [], ''));

		$session->authenticatedRawRequest(
			method: 'POST',
			url: 'https://pds.test.com/xrpc/com.atproto.repo.uploadBlob',
			body: 'x',
			contentType: 'image/png',
			headers: ['content-type' => 'application/cbor'],   // lowercase variant
		);

		self::assertSame('application/cbor', $mock->sentRequests[0]->getHeaderLine('Content-Type'));
	}

	// ──────────────────────────────────────────────────────────
	// authenticatedRequest() must remain unchanged
	// ──────────────────────────────────────────────────────────

	public function testAuthenticatedRequestStillJsonEncodesArrayBody(): void
	{
		[$session, $mock] = $this->makeSession();
		$mock->addResponse(new Response(200, ['Content-Type' => 'application/json'], '{"ok":true}'));

		$session->authenticatedRequest('POST', 'https://pds.test.com/xrpc/com.atproto.repo.createRecord', [
			'repo' => 'did:plc:test',
			'collection' => 'app.bsky.feed.post',
			'record' => ['text' => 'hello'],
		]);

		$sent = $mock->sentRequests[0];
		self::assertSame('application/json', $sent->getHeaderLine('Content-Type'));
		$decoded = json_decode((string) $sent->getBody(), true);
		self::assertSame('did:plc:test', $decoded['repo']);
		self::assertSame('hello', $decoded['record']['text']);
	}

	// ──────────────────────────────────────────────────────────
	// Helpers
	// ──────────────────────────────────────────────────────────

	/**
	 * @return array{0: Session, 1: MockHttpClient}
	 */
	private function makeSession(?\DateTimeImmutable $expiresAt = null): array
	{
		$mock = new MockHttpClient();
		$factory = new HttpFactory();
		$sessionStore = new InMemorySessionStore();

		$config = new ClientConfig(
			clientId: 'https://app.test.com/client-metadata',
			redirectUri: 'https://app.test.com/callback',
			scope: 'atproto transition:generic',
			clientName: 'Test',
			privateKey: self::$clientPem,
		);

		$oauth = new OAuthClient(
			config: $config,
			sessionStore: $sessionStore,
			stateStore: new InMemoryStateStore(),
			httpClient: $mock,
			requestFactory: $factory,
			streamFactory: $factory,
			ssrfProtection: false,
		);

		$stored = new StoredSession(
			did: 'did:plc:test',
			handle: 'test.bsky.social',
			pdsUrl: 'https://pds.test.com',
			authServerIssuer: 'https://auth.test.com',
			tokenEndpoint: 'https://auth.test.com/token',
			accessToken: 'test-access-token',
			refreshToken: 'test-refresh-token',
			dpopPrivateKeyPem: self::$dpopPem,
			expiresAt: $expiresAt ?? new \DateTimeImmutable('+1 hour'),
			scope: 'atproto transition:generic',
		);

		$sessionStore->save($stored);

		$session = $oauth->restoreSession('did:plc:test');
		self::assertNotNull($session);

		return [$session, $mock];
	}
}
