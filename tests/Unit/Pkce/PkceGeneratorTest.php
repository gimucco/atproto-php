<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Pkce;

use Gimucco\Atproto\Internal\Pkce\PkceGenerator;
use PHPUnit\Framework\TestCase;

final class PkceGeneratorTest extends TestCase
{
	public function testGenerateReturnsArrayWithVerifierAndChallengeKeys(): void
	{
		$result = PkceGenerator::generate();

		self::assertArrayHasKey('verifier', $result);
		self::assertArrayHasKey('challenge', $result);
	}

	public function testVerifierIsBase64UrlEncoded43Chars(): void
	{
		$result = PkceGenerator::generate();

		// 32 random bytes -> base64url without padding = 43 chars
		self::assertSame(43, \strlen($result['verifier']));
		// Must only contain base64url-safe characters
		self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $result['verifier']);
	}

	public function testChallengeIsBase64UrlSha256OfVerifier(): void
	{
		$result = PkceGenerator::generate();

		// Independently compute: base64url(SHA-256(verifier))
		$expectedChallenge = rtrim(strtr(
			base64_encode(hash('sha256', $result['verifier'], true)),
			'+/',
			'-_',
		), '=');

		self::assertSame($expectedChallenge, $result['challenge']);
	}

	public function testTwoCallsProduceDifferentVerifiers(): void
	{
		$first = PkceGenerator::generate();
		$second = PkceGenerator::generate();

		self::assertNotSame($first['verifier'], $second['verifier']);
	}
}
