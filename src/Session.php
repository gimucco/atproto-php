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
		$requestBody = '';
		if ($body !== []) {
			$requestBody = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
			$headers['Content-Type'] = 'application/json';
		}

		return $this->dispatch($method, $url, $requestBody, $headers);
	}

	/**
	 * Make an authenticated request with a raw byte body and a caller-controlled
	 * Content-Type. Use this for endpoints that take binary input (e.g.,
	 * `com.atproto.repo.uploadBlob` for image/video uploads).
	 *
	 * Same guarantees as authenticatedRequest(): DPoP proof generation, nonce
	 * retry, and automatic token refresh on near-expiry.
	 *
	 * The body is sent verbatim — no JSON encoding, no transformation. If the
	 * caller also includes a `Content-Type` entry in `$headers` (any case), it
	 * wins over `$contentType`.
	 *
	 * @param string $method HTTP method (GET, POST, PUT, etc.)
	 * @param string $url Full URL to request
	 * @param string $body Raw request body bytes
	 * @param string $contentType Content-Type header value (e.g., "image/jpeg")
	 * @param array<string, string> $headers Additional headers
	 *
	 * @return ResponseInterface The response from the server
	 *
	 * @throws TokenException If token refresh fails
	 * @throws DpopException If DPoP proof generation fails
	 * @throws NetworkException On HTTP transport failures
	 * @throws SessionException If the session is expired and cannot be refreshed
	 */
	public function authenticatedRawRequest(
		string $method,
		string $url,
		string $body,
		string $contentType,
		array $headers = [],
	): ResponseInterface {
		if (!self::hasHeader($headers, 'Content-Type')) {
			$headers['Content-Type'] = $contentType;
		}

		return $this->dispatch($method, $url, $body, $headers);
	}

	/**
	 * Shared plumbing for authenticatedRequest and authenticatedRawRequest:
	 * ensure the access token is fresh, then delegate to the HTTP client.
	 *
	 * @param array<string, string> $headers
	 *
	 * @throws TokenException
	 * @throws DpopException
	 * @throws NetworkException
	 * @throws SessionException
	 */
	private function dispatch(
		string $method,
		string $url,
		string $body,
		array $headers,
	): ResponseInterface {
		if ($this->storedSession->isNearExpiry()) {
			$this->refresh();
		}

		return $this->httpClient->sendResourceRequest(
			method: $method,
			url: $url,
			accessToken: $this->storedSession->accessToken,
			dpopKey: $this->dpopKey,
			headers: $headers,
			body: $body,
		);
	}

	/**
	 * Case-insensitive presence check for an HTTP header name in an array.
	 *
	 * @param array<string, string> $headers
	 */
	private static function hasHeader(array $headers, string $name): bool
	{
		foreach (array_keys($headers) as $key) {
			if (strcasecmp((string) $key, $name) === 0) {
				return true;
			}
		}

		return false;
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
