<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Dpop;

/**
 * Tracks DPoP nonces per server origin. Nonces are keyed by the scheme+host
 * portion of the URL, since a single auth server or PDS issues one nonce for
 * all its endpoints.
 *
 * @internal
 */
final class NonceStore
{
	/** @var array<string, string> */
	private array $nonces = [];

	public function get(string $url): ?string
	{
		$origin = self::originOf($url);

		return $this->nonces[$origin] ?? null;
	}

	public function set(string $url, string $nonce): void
	{
		$origin = self::originOf($url);
		$this->nonces[$origin] = $nonce;
	}

	private static function originOf(string $url): string
	{
		$parsed = parse_url($url);

		$scheme = $parsed['scheme'] ?? 'https';
		$host = $parsed['host'] ?? '';
		$port = isset($parsed['port']) ? ':'.$parsed['port'] : '';

		return $scheme.'://'.$host.$port;
	}
}
