<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Jwt;

use Gimucco\Atproto\Internal\Jwt\ClientAssertion;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use PHPUnit\Framework\TestCase;

final class ClientAssertionTest extends TestCase
{
	private static \Jose\Component\Core\JWK $jwk;

	public static function setUpBeforeClass(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		self::$jwk = KeyManager::privateKeyToJwk($pem);
	}

	public function testGenerateProducesJwtWithCorrectHeader(): void
	{
		$assertion = new ClientAssertion();
		$jwt = $assertion->generate(
			'https://example.com/client-metadata',
			'https://auth.example.com',
			self::$jwk,
		);

		$decoded = self::decodeJwt($jwt);

		self::assertSame('ES256', $decoded['header']['alg']);
	}

	public function testGenerateProducesJwtWithCorrectPayload(): void
	{
		$clientId = 'https://example.com/client-metadata';
		$audience = 'https://auth.example.com';

		$assertion = new ClientAssertion();
		$jwt = $assertion->generate($clientId, $audience, self::$jwk);

		$decoded = self::decodeJwt($jwt);

		self::assertSame($clientId, $decoded['payload']['iss']);
		self::assertSame($clientId, $decoded['payload']['sub']);
		self::assertSame($audience, $decoded['payload']['aud']);
		self::assertArrayHasKey('jti', $decoded['payload']);
		self::assertIsString($decoded['payload']['jti']);
		self::assertArrayHasKey('iat', $decoded['payload']);
		self::assertIsInt($decoded['payload']['iat']);
	}

	public function testTwoCallsProduceDifferentJtiValues(): void
	{
		$assertion = new ClientAssertion();

		$jwt1 = $assertion->generate(
			'https://example.com/client-metadata',
			'https://auth.example.com',
			self::$jwk,
		);
		$jwt2 = $assertion->generate(
			'https://example.com/client-metadata',
			'https://auth.example.com',
			self::$jwk,
		);

		$decoded1 = self::decodeJwt($jwt1);
		$decoded2 = self::decodeJwt($jwt2);

		self::assertNotSame($decoded1['payload']['jti'], $decoded2['payload']['jti']);
	}

	private static function base64urlDecode(string $data): string
	{
		return base64_decode(strtr($data, '-_', '+/'), true);
	}

	/**
	 * @return array{header: array<string, mixed>, payload: array<string, mixed>}
	 */
	private static function decodeJwt(string $jwt): array
	{
		$parts = explode('.', $jwt);

		return [
			'header' => json_decode(self::base64urlDecode($parts[0]), true),
			'payload' => json_decode(self::base64urlDecode($parts[1]), true),
		];
	}
}
