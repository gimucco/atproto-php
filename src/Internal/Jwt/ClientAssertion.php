<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Jwt;

use Gimucco\Atproto\Exception\AuthorizationException;
use Jose\Component\Core\JWK;

/**
 * Builds the private_key_jwt client assertion for token endpoint authentication.
 *
 * @internal
 */
final class ClientAssertion
{
	private readonly KeyManager $keyManager;

	public function __construct()
	{
		$this->keyManager = new KeyManager();
	}

	/**
	 * @param string $clientId The client_id URL
	 * @param string $audience The authorization server issuer URL
	 * @param JWK $privateKey The client's ES256 private key
	 *
	 * @return string Compact-serialized JWT
	 *
	 * @throws AuthorizationException
	 */
	public function generate(string $clientId, string $audience, JWK $privateKey): string
	{
		$kid = $privateKey->has('kid') ? $privateKey->get('kid') : null;

		/** @var array<string, string> $header */
		$header = array_filter([
			'alg' => 'ES256',
			'kid' => $kid,
		], static fn(mixed $v): bool => $v !== null);

		$payload = [
			'iss' => $clientId,
			'sub' => $clientId,
			'aud' => $audience,
			'jti' => self::base64url(random_bytes(16)),
			'iat' => time(),
		];

		try {
			return $this->keyManager->sign($header, $payload, $privateKey);
		} catch (\Throwable $e) {
			throw new AuthorizationException('Failed to generate client assertion: '.$e->getMessage(), 0, $e);
		}
	}

	private static function base64url(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
