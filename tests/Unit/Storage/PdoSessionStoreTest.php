<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage;

use Gimucco\Atproto\Storage\Pdo\Schema;
use Gimucco\Atproto\Storage\PdoSessionStore;
use Gimucco\Atproto\StoredSession;
use PHPUnit\Framework\TestCase;

final class PdoSessionStoreTest extends TestCase
{
	private \PDO $pdo;

	protected function setUp(): void
	{
		$this->pdo = new \PDO('sqlite::memory:');
		$this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

		$tables = Schema::createTablesSql('sqlite');
		$this->pdo->exec($tables['sessions']);
		$this->pdo->exec($tables['states']);
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

	public function testSaveThenFindByDidReturnsSession(): void
	{
		$store = new PdoSessionStore($this->pdo);
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

	public function testFindByDidReturnsNullForUnknown(): void
	{
		$store = new PdoSessionStore($this->pdo);

		self::assertNull($store->findByDid('did:plc:unknown'));
	}

	public function testDeleteRemovesSession(): void
	{
		$store = new PdoSessionStore($this->pdo);
		$session = $this->createSession();

		$store->save($session);
		$store->delete('did:plc:test123');

		self::assertNull($store->findByDid('did:plc:test123'));
	}

	public function testEncryptionPassphraseRoundTripsCorrectly(): void
	{
		$store = new PdoSessionStore($this->pdo, passphrase: 'test-passphrase');
		$session = $this->createSession();

		$store->save($session);

		$found = $store->findByDid('did:plc:test123');
		self::assertNotNull($found);
		self::assertSame('access_token_value', $found->accessToken);
		self::assertSame('refresh_token_value', $found->refreshToken);
		self::assertSame('fake-pem', $found->dpopPrivateKeyPem);
	}

	public function testSaveOverwritesExistingSession(): void
	{
		$store = new PdoSessionStore($this->pdo);

		$store->save($this->createSession());

		$updated = new StoredSession(
			did: 'did:plc:test123',
			handle: 'updated.bsky.social',
			pdsUrl: 'https://pds.example.com',
			authServerIssuer: 'https://auth.example.com',
			tokenEndpoint: 'https://auth.example.com/token',
			accessToken: 'new_access_token',
			refreshToken: 'new_refresh_token',
			dpopPrivateKeyPem: 'new-pem',
			expiresAt: new \DateTimeImmutable('+2 hours'),
			scope: 'atproto',
		);
		$store->save($updated);

		$found = $store->findByDid('did:plc:test123');
		self::assertNotNull($found);
		self::assertSame('updated.bsky.social', $found->handle);
		self::assertSame('new_access_token', $found->accessToken);
	}
}
