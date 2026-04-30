<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

use Gimucco\Atproto\Exception\DpopException;
use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\Exception\TokenException;
use Gimucco\Atproto\Internal\Http\OAuthHttpClient;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use Jose\Component\Core\JWK;
use Psr\Http\Message\ResponseInterface;

/**
 * Represents an active authenticated session with a user's PDS.
 *
 * Provides methods to make authenticated requests, refresh tokens,
 * and check session state. DPoP proofs and nonce handling are automatic.
 */
final class Session
{
	public readonly string $did;
	public readonly string $handle;
	public readonly string $pdsUrl;
	private readonly JWK $dpopKey;

	/**
	 * @internal Use OAuthClient::completeAuthorization() or OAuthClient::restoreSession()
	 */
	public function __construct(
		private StoredSession $storedSession,
		private readonly OAuthHttpClient $httpClient,
		private readonly OAuthClient $oauthClient,
	) {
		$this->did = $storedSession->did;
		$this->handle = $storedSession->handle;
		$this->pdsUrl = $storedSession->pdsUrl;
		$this->dpopKey = KeyManager::privateKeyToJwk($storedSession->dpopPrivateKeyPem);
	}

	/**
	 * Make an authenticated request to the user's PDS or any AT Protocol resource server.
	 *
	 * Automatically handles DPoP proof generation and nonce retry. If the access token
	 * is near expiry, it will be refreshed before the request is sent.
	 *
	 * @param string $method HTTP method (GET, POST, etc.)
	 * @param string $url Full URL to request
	 * @param array<string, mixed> $body Request body (will be JSON-encoded for POST/PUT/PATCH)
	 * @param array<string, string> $headers Additional headers
	 *
	 * @return ResponseInterface The response from the server
	 *
	 * @throws TokenException If token refresh fails
	 * @throws DpopException If DPoP proof generation fails
	 * @throws NetworkException On HTTP transport failures
	 * @throws SessionException If the session is expired and cannot be refreshed
	 */
	public function authenticatedRequest(
		string $method,
		string $url,
		array $body = [],
		array $headers = [],
	): ResponseInterface {
		if ($this->storedSession->isNearExpiry()) {
			$this->refresh();
		}

		$requestBody = '';
		if ($body !== []) {
			$requestBody = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
			$headers['Content-Type'] = 'application/json';
		}

		return $this->httpClient->sendResourceRequest(
			method: $method,
			url: $url,
			accessToken: $this->storedSession->accessToken,
			dpopKey: $this->dpopKey,
			headers: $headers,
			body: $requestBody,
		);
	}

	/**
	 * Force a token refresh.
	 *
	 * @throws TokenException If the refresh fails
	 * @throws NetworkException On HTTP transport failures
	 */
	public function refresh(): void
	{
		$this->storedSession = $this->oauthClient->refreshSession($this->storedSession);
	}

	public function isExpired(): bool
	{
		return $this->storedSession->isExpired();
	}

	public function expiresAt(): \DateTimeImmutable
	{
		return $this->storedSession->expiresAt;
	}

	public function scope(): string
	{
		return $this->storedSession->scope;
	}

	public function accessToken(): string
	{
		return $this->storedSession->accessToken;
	}
}
