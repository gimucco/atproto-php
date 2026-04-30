<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Resolver;

use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Exception\ResolutionException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Resolves an AT Protocol handle to a DID.
 *
 * Tries DNS TXT record (_atproto.{handle}) first, then falls back to
 * the HTTPS well-known endpoint (https://{handle}/.well-known/atproto-did).
 *
 * @internal
 */
final class HandleResolver
{
	public function __construct(
		private readonly ClientInterface $httpClient,
		private readonly RequestFactoryInterface $requestFactory,
	) {}

	/**
	 * @param string $handle AT Protocol handle (e.g., alice.bsky.social)
	 *
	 * @return string The resolved DID
	 *
	 * @throws ResolutionException If the handle cannot be resolved
	 * @throws NetworkException On HTTP transport failures
	 */
	public function resolve(string $handle): string
	{
		$handle = strtolower(trim($handle));

		if (str_starts_with($handle, '@')) {
			$handle = substr($handle, 1);
		}

		if (str_starts_with($handle, 'did:')) {
			return $handle;
		}

		$did = $this->resolveViaDns($handle);
		if ($did !== null) {
			return $did;
		}

		return $this->resolveViaHttps($handle);
	}

	private function resolveViaDns(string $handle): ?string
	{
		$records = @dns_get_record('_atproto.'.$handle, DNS_TXT);
		if (!\is_array($records)) {
			return null;
		}

		foreach ($records as $record) {
			$txt = $record['txt'] ?? '';
			if (str_starts_with($txt, 'did=')) {
				return substr($txt, 4);
			}
		}

		return null;
	}

	/**
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	private function resolveViaHttps(string $handle): string
	{
		$url = 'https://'.$handle.'/.well-known/atproto-did';

		try {
			$request = $this->requestFactory->createRequest('GET', $url);
			$response = $this->httpClient->sendRequest($request);
		} catch (ClientExceptionInterface $e) {
			throw new NetworkException('HTTP request failed during handle resolution: '.$e->getMessage(), 0, $e);
		}

		if ($response->getStatusCode() !== 200) {
			throw new ResolutionException('Failed to resolve handle "'.$handle.'": HTTP '.$response->getStatusCode());
		}

		$body = trim((string) $response->getBody());

		if (!str_starts_with($body, 'did:')) {
			throw new ResolutionException('Invalid response from handle resolution for "'.$handle.'"');
		}

		return $body;
	}
}
