<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit;

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\ClientMetadataBuilder;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use PHPUnit\Framework\TestCase;

final class ClientMetadataBuilderTest extends TestCase
{
	private static ClientConfig $config;

	public static function setUpBeforeClass(): void
	{
		$pem = KeyManager::generateDpopKeyPem();

		self::$config = new ClientConfig(
			clientId: 'https://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback',
			scope: 'atproto transition:generic',
			clientName: 'Test App',
			privateKey: $pem,
		);
	}

	public function testFromConfigReturnsExpectedFields(): void
	{
		$metadata = ClientMetadataBuilder::fromConfig(self::$config);

		self::assertSame('https://example.com/client-metadata.json', $metadata['client_id']);
		self::assertSame('Test App', $metadata['client_name']);
		self::assertSame(['authorization_code', 'refresh_token'], $metadata['grant_types']);
		self::assertSame(['code'], $metadata['response_types']);
		self::assertSame(['https://example.com/callback'], $metadata['redirect_uris']);
		self::assertSame('atproto transition:generic', $metadata['scope']);
		self::assertSame('web', $metadata['application_type']);
	}

	public function testDpopBoundAccessTokensIsTrue(): void
	{
		$metadata = ClientMetadataBuilder::fromConfig(self::$config);

		self::assertTrue($metadata['dpop_bound_access_tokens']);
	}

	public function testTokenEndpointAuthMethodIsPrivateKeyJwt(): void
	{
		$metadata = ClientMetadataBuilder::fromConfig(self::$config);

		self::assertSame('private_key_jwt', $metadata['token_endpoint_auth_method']);
	}

	public function testRedirectUrisIncludesAdditionalUris(): void
	{
		$config = new ClientConfig(
			clientId: 'https://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback/login',
			scope: 'atproto',
			clientName: 'Test App',
			privateKey: self::$config->privateKey,
			additionalRedirectUris: [
				'https://example.com/callback/link',
				'https://example.com/callback/admin',
			],
		);

		$metadata = ClientMetadataBuilder::fromConfig($config);

		self::assertSame(
			[
				'https://example.com/callback/login',
				'https://example.com/callback/link',
				'https://example.com/callback/admin',
			],
			$metadata['redirect_uris'],
		);
	}

	public function testJwksFromConfigReturnsArrayWithPublicKey(): void
	{
		$jwks = ClientMetadataBuilder::jwksFromConfig(self::$config);

		self::assertArrayHasKey('keys', $jwks);
		self::assertCount(1, $jwks['keys']);

		$key = $jwks['keys'][0];
		self::assertSame('EC', $key['kty']);
		self::assertSame('P-256', $key['crv']);
		self::assertArrayHasKey('x', $key);
		self::assertArrayHasKey('y', $key);
		self::assertArrayNotHasKey('d', $key);
		self::assertSame('sig', $key['use']);
		self::assertSame('ES256', $key['alg']);
	}
}
