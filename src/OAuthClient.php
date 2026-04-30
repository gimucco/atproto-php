<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

use Gimucco\Atproto\Exception\AuthorizationException;
use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Exception\ResolutionException;
use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\Exception\TokenException;
use Gimucco\Atproto\Internal\Dpop\NonceStore;
use Gimucco\Atproto\Internal\Http\OAuthHttpClient;
use Gimucco\Atproto\Internal\Http\SafeHttpClient;
use Gimucco\Atproto\Internal\Http\SsrfGuard;
use Gimucco\Atproto\Internal\Jwt\ClientAssertion;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use Gimucco\Atproto\Internal\Pkce\PkceGenerator;
use Gimucco\Atproto\Internal\Resolver\AuthServerResolver;
use Gimucco\Atproto\Internal\Resolver\DidResolver;
use Gimucco\Atproto\Internal\Resolver\HandleResolver;
use Jose\Component\Core\JWK;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Main entry point for AT Protocol OAuth 2.1 authentication.
 *
 * Implements the full confidential-client flow: handle/DID resolution,
 * PAR, PKCE, DPoP, token exchange, and session management.
 *
 * Portions of this file are adapted from Automattic/wordpress-atmosphere
 * (https://github.com/Automattic/wordpress-atmosphere), licensed under
 * GPL-2.0-or-later. Original copyright Automattic Inc.
 */
final class OAuthClient
{
	private readonly HandleResolver $handleResolver;
	private readonly DidResolver $didResolver;
	private readonly AuthServerResolver $authServerResolver;
	private readonly ClientAssertion $clientAssertion;
	private readonly OAuthHttpClient $oauthHttp;
	private readonly NonceStore $nonceStore;
	private readonly JWK $clientPrivateKey;
	private readonly LoggerInterface $logger;

	/**
	 * @param ClientConfig $config Client configuration
	 * @param SessionStoreInterface $sessionStore Storage for authenticated sessions
	 * @param StateStoreInterface $stateStore Storage for PKCE verifiers and pending auth states
	 * @param ClientInterface $httpClient PSR-18 HTTP client
	 * @param RequestFactoryInterface $requestFactory PSR-17 request factory
	 * @param StreamFactoryInterface $streamFactory PSR-17 stream factory
	 * @param LoggerInterface|null $logger Optional PSR-3 logger
	 * @param bool $ssrfProtection Whether to wrap the HTTP client with SSRF protection (default: true).
	 *                             Disable only in tests against mock servers.
	 */
	public function __construct(
		private readonly ClientConfig $config,
		private readonly SessionStoreInterface $sessionStore,
		private readonly StateStoreInterface $stateStore,
		ClientInterface $httpClient,
		RequestFactoryInterface $requestFactory,
		StreamFactoryInterface $streamFactory,
		?LoggerInterface $logger = null,
		bool $ssrfProtection = true,
	) {
		$this->logger = $logger ?? new NullLogger();

		if ($ssrfProtection) {
			$httpClient = new SafeHttpClient($httpClient, new SsrfGuard());
		}

		$this->handleResolver = new HandleResolver($httpClient, $requestFactory);
		$this->didResolver = new DidResolver($httpClient, $requestFactory);
		$this->authServerResolver = new AuthServerResolver($httpClient, $requestFactory);
		$this->clientAssertion = new ClientAssertion();
		$this->nonceStore = new NonceStore();
		$this->oauthHttp = new OAuthHttpClient($httpClient, $requestFactory, $streamFactory, $this->nonceStore, $this->logger);
		$this->clientPrivateKey = KeyManager::privateKeyToJwk($this->config->privateKey);
	}

	/**
	 * Step 1: Begin the OAuth authorization flow.
	 *
	 * Two modes are supported:
	 *
	 *  1. Identity-first (pass `$handleOrDid`): the library resolves the user's
	 *     handle/DID to a PDS, discovers the authorization server, and includes
	 *     the DID as a `login_hint` so the auth server pre-fills the identifier
	 *     field on its sign-in page.
	 *  2. Server-first (pass `$handleOrDid = null`): the library skips identity
	 *     resolution and redirects straight to the supplied authorization server
	 *     (default: https://bsky.social). The user enters their identifier on
	 *     the auth server's own page. The actual DID is determined post-auth
	 *     from the `sub` claim and resolved at that point.
	 *
	 * @param string|null $handleOrDid The user's handle/DID, or null to defer
	 *                                 identity selection to the auth server.
	 * @param string|null $state Optional custom state value (one will be generated if null)
	 * @param string|null $authorizationServer Authorization server URL to use
	 *                                         when no handle/DID is given.
	 *                                         Default: https://bsky.social.
	 *
	 * @return string The authorization URL to redirect the user to
	 *
	 * @throws ResolutionException If the handle/DID/PDS cannot be resolved
	 * @throws AuthorizationException If the PAR request fails
	 * @throws NetworkException On HTTP transport failures
	 */
	public function beginAuthorization(
		?string $handleOrDid = null,
		?string $state = null,
		?string $authorizationServer = null,
	): string {
		$did = null;
		$handle = null;
		$pdsUrl = null;

		if ($handleOrDid !== null && $handleOrDid !== '') {
			$did = $this->handleResolver->resolve($handleOrDid);
			$identity = $this->didResolver->resolve($did);
			$pdsUrl = $identity['pds'];
			$handle = $identity['handle'] ?? $handleOrDid;
			$authServer = $this->authServerResolver->resolve($pdsUrl);
		} else {
			$authServer = $this->authServerResolver->resolveDirect(
				$authorizationServer ?? 'https://bsky.social',
			);
		}

		$pkce = PkceGenerator::generate();
		$dpopKeyPem = KeyManager::generateDpopKeyPem();
		$dpopKey = KeyManager::privateKeyToJwk($dpopKeyPem);

		$state ??= self::generateState();

		$this->stateStore->save($state, [
			'did' => $did,
			'handle' => $handle,
			'pds_url' => $pdsUrl,
			'auth_server' => $authServer,
			'code_verifier' => $pkce['verifier'],
			'dpop_key_pem' => $dpopKeyPem,
		], 600);

		$authServerIssuer = (string) ($authServer['issuer_url'] ?? $authServer['issuer'] ?? '');
		$parEndpoint = (string) $authServer['pushed_authorization_request_endpoint'];
		$authEndpoint = (string) $authServer['authorization_endpoint'];

		$clientAssertionJwt = $this->clientAssertion->generate(
			$this->config->clientId,
			$authServerIssuer,
			$this->clientPrivateKey,
		);

		$parBody = [
			'client_id' => $this->config->clientId,
			'redirect_uri' => $this->config->redirectUri,
			'response_type' => 'code',
			'scope' => $this->config->scope,
			'state' => $state,
			'code_challenge' => $pkce['challenge'],
			'code_challenge_method' => 'S256',
			'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			'client_assertion' => $clientAssertionJwt,
		];

		if ($did !== null) {
			$parBody['login_hint'] = $did;
		}

		$response = $this->oauthHttp->sendTokenRequest($parEndpoint, $parBody, $dpopKey);

		/** @var array{request_uri?: string, error?: string, error_description?: string}|null $data */
		$data = json_decode((string) $response->getBody(), true);

		if ($response->getStatusCode() >= 400 || !\is_array($data) || empty($data['request_uri'])) {
			$error = $data['error'] ?? 'par_failed';
			$description = $data['error_description'] ?? 'Pushed Authorization Request failed';

			throw new AuthorizationException($error.': '.$description);
		}

		$params = http_build_query([
			'client_id' => $this->config->clientId,
			'request_uri' => $data['request_uri'],
		]);

		return $authEndpoint.'?'.$params;
	}

	/**
	 * Step 2: Complete the OAuth authorization flow after the user returns.
	 *
	 * Exchanges the authorization code for tokens, validates the sub claim,
	 * and creates a session.
	 *
	 * @param string $code The authorization code from the callback
	 * @param string $state The state parameter from the callback
	 * @param string $iss The issuer parameter from the callback
	 *
	 * @return Session The authenticated session
	 *
	 * @throws AuthorizationException If state is invalid or issuer doesn't match
	 * @throws TokenException If the token exchange fails
	 * @throws NetworkException On HTTP transport failures
	 */
	public function completeAuthorization(string $code, string $state, string $iss): Session
	{
		$stateData = $this->stateStore->get($state);
		if ($stateData === null) {
			throw new AuthorizationException('Invalid or expired OAuth state');
		}

		$this->stateStore->delete($state);

		/** @var array<string, mixed> $authServer */
		$authServer = $stateData['auth_server'];
		$authServerIssuer = (string) ($authServer['issuer_url'] ?? $authServer['issuer'] ?? '');

		if ($iss !== $authServerIssuer) {
			throw new AuthorizationException(
				'Issuer mismatch: expected "'.$authServerIssuer.'", got "'.$iss.'"',
			);
		}

		$tokenEndpoint = (string) $authServer['token_endpoint'];
		$dpopKeyPem = (string) $stateData['dpop_key_pem'];
		$dpopKey = KeyManager::privateKeyToJwk($dpopKeyPem);

		$clientAssertionJwt = $this->clientAssertion->generate(
			$this->config->clientId,
			$authServerIssuer,
			$this->clientPrivateKey,
		);

		$tokenBody = [
			'grant_type' => 'authorization_code',
			'code' => $code,
			'redirect_uri' => $this->config->redirectUri,
			'client_id' => $this->config->clientId,
			'code_verifier' => (string) $stateData['code_verifier'],
			'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			'client_assertion' => $clientAssertionJwt,
		];

		$response = $this->oauthHttp->sendTokenRequest($tokenEndpoint, $tokenBody, $dpopKey);

		/** @var array{access_token?: string, refresh_token?: string, expires_in?: int, scope?: string, sub?: string, error?: string, error_description?: string, error_uri?: string}|null $tokenData */
		$tokenData = json_decode((string) $response->getBody(), true);

		if ($response->getStatusCode() >= 400 || !\is_array($tokenData) || empty($tokenData['access_token'])) {
			throw new TokenException(
				error: $tokenData['error'] ?? 'token_exchange_failed',
				errorDescription: $tokenData['error_description'] ?? 'Token exchange failed',
				errorUri: $tokenData['error_uri'] ?? '',
			);
		}

		$sub = $tokenData['sub'] ?? '';
		if ($sub === '') {
			throw new AuthorizationException('Token response missing required `sub` claim');
		}

		$expectedDid = $stateData['did'] ?? null;

		// In identity-first mode, sub MUST match the DID we resolved up front.
		// In server-first mode, sub IS the user's DID — discovered now.
		if ($expectedDid !== null && $sub !== $expectedDid) {
			throw new AuthorizationException(
				'Sub mismatch: expected "'.$expectedDid.'", got "'.$sub.'"',
			);
		}

		$pdsUrl = $stateData['pds_url'] ?? null;
		$handle = $stateData['handle'] ?? null;

		// Server-first flow: we don't know the user's PDS or handle yet —
		// resolve them now from the DID returned by the auth server.
		if ($pdsUrl === null) {
			$identity = $this->didResolver->resolve($sub);
			$pdsUrl = $identity['pds'];
			$handle = $identity['handle'] ?? '';
		}

		$storedSession = new StoredSession(
			did: $sub,
			handle: (string) ($handle ?? ''),
			pdsUrl: (string) $pdsUrl,
			authServerIssuer: $authServerIssuer,
			tokenEndpoint: $tokenEndpoint,
			accessToken: $tokenData['access_token'],
			refreshToken: $tokenData['refresh_token'] ?? '',
			dpopPrivateKeyPem: $dpopKeyPem,
			expiresAt: (new \DateTimeImmutable())->modify('+'.($tokenData['expires_in'] ?? 300).' seconds'),
			scope: $tokenData['scope'] ?? $this->config->scope,
		);

		$this->sessionStore->save($storedSession);

		return new Session($storedSession, $this->oauthHttp, $this);
	}

	/**
	 * Restore an existing session from storage.
	 *
	 * @param string $did The DID to look up
	 *
	 * @return Session|null The restored session, or null if not found
	 *
	 * @throws SessionException If the session cannot be restored
	 */
	public function restoreSession(string $did): ?Session
	{
		$stored = $this->sessionStore->findByDid($did);
		if ($stored === null) {
			return null;
		}

		return new Session($stored, $this->oauthHttp, $this);
	}

	/**
	 * Revoke and delete a session.
	 *
	 * @param Session $session The session to revoke
	 */
	public function revokeSession(Session $session): void
	{
		$this->sessionStore->delete($session->did);
	}

	/**
	 * Refresh a session's tokens.
	 *
	 * @param StoredSession $session The session to refresh
	 *
	 * @return StoredSession The updated session with new tokens
	 *
	 * @throws TokenException If the refresh fails
	 * @throws NetworkException On HTTP transport failures
	 *
	 * @internal Called by Session::refresh()
	 */
	public function refreshSession(StoredSession $session): StoredSession
	{
		if ($session->refreshToken === '') {
			throw new TokenException(
				error: 'no_refresh_token',
				errorDescription: 'No refresh token available',
			);
		}

		$dpopKey = KeyManager::privateKeyToJwk($session->dpopPrivateKeyPem);

		$clientAssertionJwt = $this->clientAssertion->generate(
			$this->config->clientId,
			$session->authServerIssuer,
			$this->clientPrivateKey,
		);

		$body = [
			'grant_type' => 'refresh_token',
			'refresh_token' => $session->refreshToken,
			'client_id' => $this->config->clientId,
			'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			'client_assertion' => $clientAssertionJwt,
		];

		$response = $this->oauthHttp->sendTokenRequest($session->tokenEndpoint, $body, $dpopKey);

		/** @var array{access_token?: string, refresh_token?: string, expires_in?: int, error?: string, error_description?: string, error_uri?: string}|null $data */
		$data = json_decode((string) $response->getBody(), true);

		if ($response->getStatusCode() >= 400 || !\is_array($data) || empty($data['access_token'])) {
			$this->logger->error('Token refresh failed', ['did' => $session->did, 'error' => $data['error'] ?? 'unknown']);

			throw new TokenException(
				error: $data['error'] ?? 'refresh_failed',
				errorDescription: $data['error_description'] ?? 'Token refresh failed',
				errorUri: $data['error_uri'] ?? '',
			);
		}

		$session->accessToken = $data['access_token'];
		$session->expiresAt = (new \DateTimeImmutable())->modify('+'.($data['expires_in'] ?? 300).' seconds');

		if (!empty($data['refresh_token'])) {
			$session->refreshToken = $data['refresh_token'];
		}

		$this->sessionStore->save($session);

		return $session;
	}

	private static function generateState(): string
	{
		return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
	}
}
