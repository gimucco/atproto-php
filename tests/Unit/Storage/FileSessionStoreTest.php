<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage;

use Gimucco\Atproto\Storage\FileSessionStore;
use Gimucco\Atproto\StoredSession;
use PHPUnit\Framework\TestCase;

final class FileSessionStoreTest extends TestCase
{
	private string $directory;

	protected function setUp(): void
	{
		$this->directory = sys_get_temp_dir().'/atproto_test_'.uniqid('', true);
	}

	protected function tearDown(): void
	{
		if (is_dir($this->directory)) {
			$files = glob($this->directory.'/*');
			if ($files !== false) {
				foreach ($files as $file) {
					unlink($file);
				}
			}
			rmdir($this->directory);
		}
	}

	private function createSession(string $did = 'did:plc:test123'): StoredSession
	{
		return new StoredSession(
			did: $did,
			handle: 'test.bsky.social',
			pdsUrl: 'https://pds.example.com',
			authServerIssuer: 'https://auth.example.com',
			tokenEndpoint: 'https://auth.example.com/token',
			accessToken: 'access_token_value',
			refreshToken: 'refresh_token_value',
			dpopPrivateKeyPem: 'fake-pem',
			expiresAt: new \DateTimeImmutable('+1 hour'),
			scope: 'atproto',
		);
	}

	public function testWithEncryptionSaveThenFindByDidReturnsCorrectData(): void
	{
		$store = new FileSessionStore($this->directory, passphrase: 'test-passphrase');
		$session = $this->createSession();

		$store->save($session);

		$found = $store->findByDid('did:plc:test123');
		self::assertNotNull($found);
		self::assertSame('did:plc:test123', $found->did);
		self::assertSame('test.bsky.social', $found->handle);
		self::assertSame('access_token_value', $found->accessToken);
		self::assertSame('refresh_token_value', $found->refreshToken);
		self::assertSame('fake-pem', $found->dpopPrivateKeyPem);
	}

	public function testWithoutEncryptionSaveThenFindByDidReturnsCorrectData(): void
	{
		$store = new FileSessionStore($this->directory);
		$session = $this->createSession();

		$store->save($session);

		$found = $store->findByDid('did:plc:test123');
		self::assertNotNull($found);
		self::assertSame('did:plc:test123', $found->did);
		self::assertSame('access_token_value', $found->accessToken);
	}

	public function testDeleteRemovesTheFile(): void
	{
		$store = new FileSessionStore($this->directory, passphrase: 'test-passphrase');
		$session = $this->createSession();

		$store->save($session);

		// Verify file exists
		self::assertNotNull($store->findByDid('did:plc:test123'));

		$store->delete('did:plc:test123');

		self::assertNull($store->findByDid('did:plc:test123'));
	}

	public function testFindByDidReturnsNullForUnknown(): void
	{
		$store = new FileSessionStore($this->directory);

		self::assertNull($store->findByDid('did:plc:unknown'));
	}
}
