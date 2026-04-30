<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Jwt;

use Gimucco\Atproto\Exception\ConfigurationException;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use PHPUnit\Framework\TestCase;

final class KeyManagerTest extends TestCase
{
	public function testGenerateDpopKeyPemReturnsValidPem(): void
	{
		$pem = KeyManager::generateDpopKeyPem();

		self::assertStringStartsWith('-----BEGIN', $pem);
	}

	public function testPrivateKeyToJwkFromPemReturnsJwkWithExpectedFields(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwk = KeyManager::privateKeyToJwk($pem);

		self::assertSame('EC', $jwk->get('kty'));
		self::assertSame('P-256', $jwk->get('crv'));
		self::assertTrue($jwk->has('x'));
		self::assertTrue($jwk->has('y'));
		self::assertTrue($jwk->has('d'));
	}

	public function testPrivateKeyToJwkFromArrayWorks(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwk = KeyManager::privateKeyToJwk($pem);

		// Convert to array and back
		$jwkArray = [
			'kty' => $jwk->get('kty'),
			'crv' => $jwk->get('crv'),
			'x' => $jwk->get('x'),
			'y' => $jwk->get('y'),
			'd' => $jwk->get('d'),
		];

		$jwk2 = KeyManager::privateKeyToJwk($jwkArray);

		self::assertSame('EC', $jwk2->get('kty'));
		self::assertSame('P-256', $jwk2->get('crv'));
		self::assertSame($jwk->get('x'), $jwk2->get('x'));
		self::assertSame($jwk->get('y'), $jwk2->get('y'));
		self::assertSame($jwk->get('d'), $jwk2->get('d'));
	}

	public function testPublicJwkStripsDParameter(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$privateJwk = KeyManager::privateKeyToJwk($pem);
		$publicJwk = KeyManager::publicJwk($privateJwk);

		self::assertFalse($publicJwk->has('d'));
		self::assertTrue($publicJwk->has('kty'));
		self::assertTrue($publicJwk->has('crv'));
		self::assertTrue($publicJwk->has('x'));
		self::assertTrue($publicJwk->has('y'));
	}

	public function testJwkToPublicArrayReturnsCorrectStructure(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwk = KeyManager::privateKeyToJwk($pem);
		$publicArray = KeyManager::jwkToPublicArray($jwk);

		self::assertSame('EC', $publicArray['kty']);
		self::assertSame('P-256', $publicArray['crv']);
		self::assertArrayHasKey('x', $publicArray);
		self::assertArrayHasKey('y', $publicArray);
		self::assertSame('sig', $publicArray['use']);
		self::assertSame('ES256', $publicArray['alg']);
		self::assertArrayNotHasKey('d', $publicArray);
	}

	public function testInvalidPemThrowsConfigurationException(): void
	{
		$this->expectException(ConfigurationException::class);

		KeyManager::privateKeyToJwk('not-a-valid-pem');
	}

	public function testPrivateKeyToJwkAttachesDerivedKid(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwk = KeyManager::privateKeyToJwk($pem);

		self::assertTrue($jwk->has('kid'));
		// RFC 7638 SHA-256 thumbprint base64url-encoded -> 43 chars
		self::assertSame(43, \strlen($jwk->get('kid')));
	}

	public function testKidIsDeterministicAcrossPrivateAndPublicForms(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$privateJwk = KeyManager::privateKeyToJwk($pem);
		$publicJwk = KeyManager::publicJwk($privateJwk);

		self::assertSame($privateJwk->get('kid'), $publicJwk->get('kid'));
	}

	public function testJwkToPublicArrayIncludesKid(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwk = KeyManager::privateKeyToJwk($pem);
		$publicArray = KeyManager::jwkToPublicArray($jwk);

		self::assertArrayHasKey('kid', $publicArray);
		self::assertSame($jwk->get('kid'), $publicArray['kid']);
	}

	public function testUserSuppliedKidIsPreserved(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwkArray = KeyManager::pemToJwkArray($pem);
		$jwkArray['kid'] = 'my-custom-kid';

		$jwk = KeyManager::privateKeyToJwk($jwkArray);

		self::assertSame('my-custom-kid', $jwk->get('kid'));
	}

	public function testPemToJwkArrayPadsToThirtyTwoBytes(): void
	{
		// Generate many keys; with padding the base64url-decoded length must always be 32.
		for ($i = 0; $i < 20; $i++) {
			$pem = KeyManager::generateDpopKeyPem();
			$arr = KeyManager::pemToJwkArray($pem);

			$xLen = \strlen(base64_decode(strtr($arr['x'], '-_', '+/'), true) ?: '');
			$yLen = \strlen(base64_decode(strtr($arr['y'], '-_', '+/'), true) ?: '');
			$dLen = \strlen(base64_decode(strtr($arr['d'], '-_', '+/'), true) ?: '');

			self::assertSame(32, $xLen, 'x not 32 bytes');
			self::assertSame(32, $yLen, 'y not 32 bytes');
			self::assertSame(32, $dLen, 'd not 32 bytes');
		}
	}

	public function testSignProducesCompactJwtWithThreeParts(): void
	{
		$pem = KeyManager::generateDpopKeyPem();
		$jwk = KeyManager::privateKeyToJwk($pem);

		$keyManager = new KeyManager();
		$jwt = $keyManager->sign(
			['alg' => 'ES256'],
			['sub' => 'test', 'iat' => time()],
			$jwk,
		);

		$parts = explode('.', $jwt);
		self::assertCount(3, $parts);

		// Each part must be non-empty
		foreach ($parts as $part) {
			self::assertNotEmpty($part);
		}
	}
}
