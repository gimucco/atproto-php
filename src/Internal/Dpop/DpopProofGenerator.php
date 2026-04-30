<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Dpop;

use Gimucco\Atproto\Exception\DpopException;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use Jose\Component\Core\JWK;

/**
 * Generates DPoP proof JWTs per RFC 9449, as required by the AT Protocol OAuth profile.
 *
 * @internal
 */
final class DpopProofGenerator
{
	private readonly KeyManager $keyManager;

	public function __construct()
	{
		$this->keyManager = new KeyManager();
	}

	/**
	 * @param JWK $privateKey The DPoP session keypair (ES256)
	 * @param string $method HTTP method (GET, POST, etc.)
	 * @param string $url Full URL of the endpoint (no query string or fragment)
	 * @param string|null $nonce Server-issued DPoP nonce
	 * @param string|null $accessToken Access token for ath claim (resource requests only)
	 *
	 * @return string Compact-serialized DPoP proof JWT
	 *
	 * @throws DpopException
	 */
	public function generate(
		JWK $privateKey,
		string $method,
		string $url,
		?string $nonce = null,
		?string $accessToken = null,
	): string {
		$publicJwk = KeyManager::publicJwk($privateKey);

		$header = [
			'typ' => 'dpop+jwt',
			'alg' => 'ES256',
			'jwk' => [
				'kty' => $publicJwk->get('kty'),
				'crv' => $publicJwk->get('crv'),
				'x' => $publicJwk->get('x'),
				'y' => $publicJwk->get('y'),
			],
		];

		$htu = self::stripQueryAndFragment($url);

		$payload = [
			'jti' => self::base64url(random_bytes(16)),
			'htm' => strtoupper($method),
			'htu' => $htu,
			'iat' => time(),
		];

		if ($nonce !== null) {
			$payload['nonce'] = $nonce;
		}

		if ($accessToken !== null) {
			$payload['ath'] = self::base64url(hash('sha256', $accessToken, true));
		}

		try {
			return $this->keyManager->sign($header, $payload, $privateKey);
		} catch (\Throwable $e) {
			throw new DpopException('Failed to generate DPoP proof: '.$e->getMessage(), 0, $e);
		}
	}

	private static function stripQueryAndFragment(string $url): string
	{
		$parsed = parse_url($url);

		$scheme = $parsed['scheme'] ?? 'https';
		$host = $parsed['host'] ?? '';
		$port = isset($parsed['port']) ? ':'.$parsed['port'] : '';
		$path = $parsed['path'] ?? '';

		return $scheme.'://'.$host.$port.$path;
	}

	private static function base64url(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
