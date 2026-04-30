<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit;

use Gimucco\Atproto\ClientConfig;
use Gimucco\Atproto\Exception\ConfigurationException;
use Gimucco\Atproto\Internal\Jwt\KeyManager;
use PHPUnit\Framework\TestCase;

final class ClientConfigTest extends TestCase
{
	private static string $pem;

	public static function setUpBeforeClass(): void
	{
		self::$pem = KeyManager::generateDpopKeyPem();
	}

	public function testValidConfigCreatesSuccessfully(): void
	{
		$config = new ClientConfig(
			clientId: 'https://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback',
			scope: 'atproto transition:generic',
			clientName: 'Test App',
			privateKey: self::$pem,
		);

		self::assertSame('https://example.com/client-metadata.json', $config->clientId);
		self::assertSame('Test App', $config->clientName);
	}

	public function testMissingHttpsOnClientIdThrowsConfigurationException(): void
	{
		$this->expectException(ConfigurationException::class);
		$this->expectExceptionMessage('client_id must be an HTTPS URL');

		new ClientConfig(
			clientId: 'http://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback',
			scope: 'atproto',
			clientName: 'Test App',
			privateKey: self::$pem,
		);
	}

	public function testMissingAtprotoScopeThrowsConfigurationException(): void
	{
		$this->expectException(ConfigurationException::class);
		$this->expectExceptionMessage('scope must include "atproto"');

		new ClientConfig(
			clientId: 'https://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback',
			scope: 'openid profile',
			clientName: 'Test App',
			privateKey: self::$pem,
		);
	}

	public function testEmptyClientNameThrowsConfigurationException(): void
	{
		$this->expectException(ConfigurationException::class);
		$this->expectExceptionMessage('client_name must not be empty');

		new ClientConfig(
			clientId: 'https://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback',
			scope: 'atproto',
			clientName: '',
			privateKey: self::$pem,
		);
	}

	public function testEmptyPrivateKeyThrowsConfigurationException(): void
	{
		$this->expectException(ConfigurationException::class);
		$this->expectExceptionMessage('privateKey is required');

		new ClientConfig(
			clientId: 'https://example.com/client-metadata.json',
			redirectUri: 'https://example.com/callback',
			scope: 'atproto',
			clientName: 'Test App',
			privateKey: '',
		);
	}
}
