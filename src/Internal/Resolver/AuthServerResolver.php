<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Resolver;

use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Exception\ResolutionException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Discovers the authorization server for a PDS by fetching the protected
 * resource metadata, then the authorization server metadata.
 *
 * @internal
 */
final class AuthServerResolver
{
	public function __construct(
		private readonly ClientInterface $httpClient,
		private readonly RequestFactoryInterface $requestFactory,
	) {}

	/**
	 * @param string $pdsUrl The PDS base URL
	 *
	 * @return array<string, mixed> Authorization server metadata including 'issuer_url'
	 *
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	public function resolve(string $pdsUrl): array
	{
		$pdsUrl = rtrim($pdsUrl, '/');

		$issuer = self::normalizeIssuerUrl($this->fetchProtectedResourceIssuer($pdsUrl));
		$meta = $this->fetchAuthServerMetadata($issuer);

		$meta['issuer_url'] = $issuer;

		return $meta;
	}

	/**
	 * Resolve auth server metadata directly from an issuer/auth-server URL,
	 * skipping the PDS protected-resource step. Useful when the client
	 * doesn't yet know the user's identity (server-first OAuth flow).
	 *
	 * @param string $issuerUrl The authorization server issuer URL
	 *                          (e.g., https://bsky.social).
	 *
	 * @return array<string, mixed> Authorization server metadata including 'issuer_url'
	 *
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	public function resolveDirect(string $issuerUrl): array
	{
		$issuerUrl = self::normalizeIssuerUrl($issuerUrl);

		$meta = $this->fetchAuthServerMetadata($issuerUrl);
		$meta['issuer_url'] = $issuerUrl;

		return $meta;
	}

	/**
	 * Normalize an issuer URL into the canonical form used for `.well-known`
	 * discovery: scheme + host + (optional port) + (optional path, no trailing slash).
	 * Strips query string and fragment, which are meaningless for an issuer
	 * and would otherwise produce a malformed `.well-known` URL when concatenated.
	 *
	 * @throws ResolutionException If the URL is invalid or uses an unsupported scheme
	 */
	private static function normalizeIssuerUrl(string $url): string
	{
		$parsed = parse_url($url);
		if ($parsed === false || empty($parsed['scheme']) || empty($parsed['host'])) {
			throw new ResolutionException('Invalid authorization server URL: '.$url);
		}

		$scheme = $parsed['scheme'];
		if ($scheme !== 'https' && $scheme !== 'http') {
			throw new ResolutionException('Authorization server URL must use http or https: '.$url);
		}

		$port = isset($parsed['port']) ? ':'.$parsed['port'] : '';
		$path = isset($parsed['path']) ? rtrim($parsed['path'], '/') : '';

		return $scheme.'://'.$parsed['host'].$port.$path;
	}

	/**
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	private function fetchProtectedResourceIssuer(string $pdsUrl): string
	{
		$url = $pdsUrl.'/.well-known/oauth-protected-resource';

		try {
			$request = $this->requestFactory->createRequest('GET', $url);
			$response = $this->httpClient->sendRequest($request);
		} catch (ClientExceptionInterface $e) {
			throw new NetworkException('Failed to fetch protected resource metadata: '.$e->getMessage(), 0, $e);
		}

		if ($response->getStatusCode() !== 200) {
			throw new ResolutionException('Failed to fetch protected resource metadata: HTTP '.$response->getStatusCode());
		}

		/** @var array<string, mixed>|null $data */
		$data = json_decode((string) $response->getBody(), true);

		if (!\is_array($data) || empty($data['authorization_servers'][0])) {
			throw new ResolutionException('PDS did not advertise an authorization server');
		}

		/** @var string */
		return $data['authorization_servers'][0];
	}

	/**
	 * @return array<string, mixed>
	 *
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	private function fetchAuthServerMetadata(string $issuer): array
	{
		// Callers must pre-normalize via normalizeIssuerUrl().
		$url = $issuer.'/.well-known/oauth-authorization-server';

		try {
			$request = $this->requestFactory->createRequest('GET', $url);
			$response = $this->httpClient->sendRequest($request);
		} catch (ClientExceptionInterface $e) {
			throw new NetworkException('Failed to fetch auth server metadata: '.$e->getMessage(), 0, $e);
		}

		if ($response->getStatusCode() !== 200) {
			throw new ResolutionException('Failed to fetch auth server metadata: HTTP '.$response->getStatusCode());
		}

		/** @var array<string, mixed>|null $meta */
		$meta = json_decode((string) $response->getBody(), true);

		if (!\is_array($meta)) {
			throw new ResolutionException('Invalid authorization server metadata');
		}

		self::validateMetadata($meta);

		return $meta;
	}

	/**
	 * @param array<string, mixed> $meta
	 *
	 * @throws ResolutionException
	 */
	private static function validateMetadata(array $meta): void
	{
		$required = ['authorization_endpoint', 'token_endpoint', 'pushed_authorization_request_endpoint'];

		foreach ($required as $field) {
			if (empty($meta[$field])) {
				throw new ResolutionException('Authorization server metadata missing required field: '.$field);
			}
		}
	}
}
