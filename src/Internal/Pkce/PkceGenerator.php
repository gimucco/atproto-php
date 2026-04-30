<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Pkce;

/**
 * @internal
 */
final class PkceGenerator
{
	/**
	 * @return array{verifier: string, challenge: string}
	 */
	public static function generate(): array
	{
		$verifier = self::generateVerifier();

		return [
			'verifier' => $verifier,
			'challenge' => self::generateChallenge($verifier),
		];
	}

	public static function generateVerifier(): string
	{
		return self::base64url(random_bytes(32));
	}

	public static function generateChallenge(string $verifier): string
	{
		return self::base64url(hash('sha256', $verifier, true));
	}

	private static function base64url(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
