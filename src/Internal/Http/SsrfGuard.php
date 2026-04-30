<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Http;

use Gimucco\Atproto\Exception\NetworkException;

/**
 * Validates that a URL points to a publicly routable host.
 *
 * The AT Protocol identity chain (handle → DID → PDS → auth server) walks
 * through several user-controlled values. Without this guard, a malicious
 * handle or DID document could direct the library to make requests against
 * internal infrastructure (cloud metadata services, internal APIs, etc.).
 *
 * Note: this performs a pre-flight DNS check. There is a TOCTOU window
 * between the check and the underlying HTTP client's connection. For
 * stronger protection, pin requests to a specific IP at the transport
 * layer (e.g., `CURLOPT_RESOLVE` with Guzzle).
 *
 * @internal
 */
final class SsrfGuard
{
	/**
	 * Extra IPv4 ranges not covered by FILTER_FLAG_NO_PRIV_RANGE / FILTER_FLAG_NO_RES_RANGE.
	 *
	 * @var array<int, array{network: string, prefix: int}>
	 */
	private const EXTRA_IPV4_BLOCKS = [
		['network' => '100.64.0.0', 'prefix' => 10],   // CGNAT (RFC 6598)
		['network' => '192.0.0.0',  'prefix' => 24],   // IETF protocol assignments
		['network' => '198.18.0.0', 'prefix' => 15],   // benchmarking
	];

	/**
	 * @throws NetworkException If the URL is invalid or points to a non-public host
	 */
	public function validate(string $url): void
	{
		$parsed = parse_url($url);
		if ($parsed === false) {
			throw new NetworkException('Invalid URL: '.$url);
		}

		$scheme = $parsed['scheme'] ?? '';
		if ($scheme !== 'https' && $scheme !== 'http') {
			throw new NetworkException('Only http/https URLs are allowed: '.$url);
		}

		if (!isset($parsed['host'])) {
			throw new NetworkException('URL has no host component: '.$url);
		}

		$host = trim($parsed['host'], '[]');

		$ips = $this->resolveHost($host);
		if ($ips === []) {
			throw new NetworkException('Could not resolve host: '.$host);
		}

		foreach ($ips as $ip) {
			if (!self::isPublicIp($ip)) {
				throw new NetworkException(
					'Refusing to connect to private or reserved IP: '.$ip.' ('.$host.')',
				);
			}
		}
	}

	/**
	 * @return array<int, string> Resolved IP addresses (empty if resolution fails)
	 */
	private function resolveHost(string $host): array
	{
		if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
			return [$host];
		}

		$ips = [];

		$aRecords = @dns_get_record($host, DNS_A);
		if (\is_array($aRecords)) {
			foreach ($aRecords as $record) {
				if (isset($record['ip']) && \is_string($record['ip'])) {
					$ips[] = $record['ip'];
				}
			}
		}

		$aaaaRecords = @dns_get_record($host, DNS_AAAA);
		if (\is_array($aaaaRecords)) {
			foreach ($aaaaRecords as $record) {
				if (isset($record['ipv6']) && \is_string($record['ipv6'])) {
					$ips[] = $record['ipv6'];
				}
			}
		}

		if ($ips === []) {
			$ip = gethostbyname($host);
			if ($ip !== $host && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
				$ips[] = $ip;
			}
		}

		return $ips;
	}

	public static function isPublicIp(string $ip): bool
	{
		$valid = filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
		);
		if ($valid === false) {
			return false;
		}

		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
			foreach (self::EXTRA_IPV4_BLOCKS as $block) {
				if (self::ipv4InCidr($ip, $block['network'], $block['prefix'])) {
					return false;
				}
			}
		}

		return true;
	}

	private static function ipv4InCidr(string $ip, string $network, int $prefix): bool
	{
		$ipLong = ip2long($ip);
		$netLong = ip2long($network);
		if ($ipLong === false || $netLong === false) {
			return false;
		}

		if ($prefix < 0 || $prefix > 32) {
			return false;
		}

		if ($prefix === 0) {
			return true;
		}

		$mask = -1 << (32 - $prefix);

		return ($ipLong & $mask) === ($netLong & $mask);
	}
}
