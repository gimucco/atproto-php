<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Resolver;

use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Exception\ResolutionException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Resolves a DID to a PDS URL.
 *
 * Supports did:plc (via plc.directory) and did:web resolution.
 *
 * @internal
 */
final class DidResolver
{
	private const PLC_DIRECTORY = 'https://plc.directory';

	public function __construct(
		private readonly ClientInterface $httpClient,
		private readonly RequestFactoryInterface $requestFactory,
	) {}

	/**
	 * @param string $did A DID (did:plc:xxx or did:web:domain)
	 *
	 * @return array{did: string, pds: string, handle: string|null} Resolved identity
	 *
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	public function resolve(string $did): array
	{
		$doc = $this->fetchDidDocument($did);
		$pds = self::extractPds($doc);
		$handle = self::extractHandle($doc);

		return [
			'did' => $did,
			'pds' => $pds,
			'handle' => $handle,
		];
	}

	/**
	 * @return array<string, mixed>
	 *
	 * @throws ResolutionException
	 * @throws NetworkException
	 */
	public function fetchDidDocument(string $did): array
	{
		if (str_starts_with($did, 'did:plc:')) {
			$url = self::PLC_DIRECTORY.'/'.$did;
		} elseif (str_starts_with($did, 'did:web:')) {
			$domain = substr($did, 8);
			$url = 'https://'.$domain.'/.well-known/did.json';
		} else {
			throw new ResolutionException('Unsupported DID method: '.$did);
		}

		try {
			$request = $this->requestFactory->createRequest('GET', $url);
			$response = $this->httpClient->sendRequest($request);
		} catch (ClientExceptionInterface $e) {
			throw new NetworkException('HTTP request failed during DID resolution: '.$e->getMessage(), 0, $e);
		}

		if ($response->getStatusCode() !== 200) {
			throw new ResolutionException('Failed to resolve DID "'.$did.'": HTTP '.$response->getStatusCode());
		}

		/** @var array<string, mixed>|null $doc */
		$doc = json_decode((string) $response->getBody(), true);

		if (!\is_array($doc) || !isset($doc['id'])) {
			throw new ResolutionException('Invalid DID document for "'.$did.'"');
		}

		return $doc;
	}

	/**
	 * @param array<string, mixed> $doc
	 *
	 * @throws ResolutionException
	 */
	public static function extractPds(array $doc): string
	{
		/** @var array<int, array{id?: string, type?: string, serviceEndpoint?: string}> $services */
		$services = $doc['service'] ?? [];

		foreach ($services as $service) {
			$id = $service['id'] ?? '';
			$type = $service['type'] ?? '';

			if ($id === '#atproto_pds' && $type === 'AtprotoPersonalDataServer' && isset($service['serviceEndpoint'])) {
				return $service['serviceEndpoint'];
			}
		}

		throw new ResolutionException('No PDS endpoint found in DID document');
	}

	/**
	 * @param array<string, mixed> $doc
	 */
	public static function extractHandle(array $doc): ?string
	{
		/** @var array<int, string> $aliases */
		$aliases = $doc['alsoKnownAs'] ?? [];

		foreach ($aliases as $alias) {
			if (str_starts_with($alias, 'at://')) {
				return substr($alias, 5);
			}
		}

		return null;
	}
}
