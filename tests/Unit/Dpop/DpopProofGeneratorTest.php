<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Dpop;

use Gimucco\Atproto\Internal\Dpop\DpopProofGenerator;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use PHPUnit\Framework\TestCase;

final class DpopProofGeneratorTest extends TestCase
{
	private static string $pem;

	private static \Jose\Component\Core\JWK $jwk;

	public static function setUpBeforeClass(): void
	{
		self::$pem = KeyManager::generateDpopKeyPem();
		self::$jwk = KeyManager::privateKeyToJwk(self::$pem);
	}

	public function testGenerateProducesValidJwtWithCorrectHeader(): void
	{
		$generator = new DpopProofGenerator();
		$proof = $generator->generate(self::$jwk, 'POST', 'https://example.com/token');

		$decoded = self::decodeJwt($proof);

		self::assertSame('dpop+jwt', $decoded['header']['typ']);
		self::assertSame('ES256', $decoded['header']['alg']);
		self::assertArrayHasKey('jwk', $decoded['header']);

		// The embedded JWK must be public only (no 'd' parameter)
		self::assertArrayNotHasKey('d', $decoded['header']['jwk']);
		self::assertArrayHasKey('kty', $decoded['header']['jwk']);
		self::assertArrayHasKey('crv', $decoded['header']['jwk']);
		self::assertArrayHasKey('x', $decoded['header']['jwk']);
		self::assertArrayHasKey('y', $decoded['header']['jwk']);
	}

	public function testGenerateProducesValidPayload(): void
	{
		$generator = new DpopProofGenerator();
		$proof = $generator->generate(self::$jwk, 'POST', 'https://example.com/token');

		$decoded = self::decodeJwt($proof);

		self::assertArrayHasKey('jti', $decoded['payload']);
		self::assertSame('POST', $decoded['payload']['htm']);
		self::assertSame('https://example.com/token', $decoded['payload']['htu']);
		self::assertArrayHasKey('iat', $decoded['payload']);
		self::assertIsInt($decoded['payload']['iat']);
	}

	public function testNonceAppearsInPayloadWhenProvided(): void
	{
		$generator = new DpopProofGenerator();
		$proof = $generator->generate(
			self::$jwk,
			'POST',
			'https://example.com/token',
			nonce: 'server-nonce-123',
		);

		$decoded = self::decodeJwt($proof);

		self::assertSame('server-nonce-123', $decoded['payload']['nonce']);
	}

	public function testAthClaimPresentWhenAccessTokenProvided(): void
	{
		$generator = new DpopProofGenerator();
		$accessToken = 'my-access-token-value';

		$proof = $generator->generate(
			self::$jwk,
			'GET',
			'https://pds.example.com/xrpc/com.atproto.repo.getRecord',
			accessToken: $accessToken,
		);

		$decoded = self::decodeJwt($proof);

		$expectedAth = rtrim(strtr(
			base64_encode(hash('sha256', $accessToken, true)),
			'+/',
			'-_',
		), '=');

		self::assertSame($expectedAth, $decoded['payload']['ath']);
	}

	public function testHtuStripsQueryString(): void
	{
		$generator = new DpopProofGenerator();
		$proof = $generator->generate(
			self::$jwk,
			'GET',
			'https://example.com/token?foo=bar&baz=qux',
		);

		$decoded = self::decodeJwt($proof);

		self::assertSame('https://example.com/token', $decoded['payload']['htu']);
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
