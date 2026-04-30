<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage;

use Gimucco\Atproto\Storage\InMemorySessionStore;
use Gimucco\Atproto\StoredSession;
use PHPUnit\Framework\TestCase;

final class InMemorySessionStoreTest extends TestCase
{
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
		$store = new InMemorySessionStore();
		$session = $this->createSession();

		$store->save($session);

		$found = $store->findByDid('did:plc:test123');
		self::assertNotNull($found);
		self::assertSame('did:plc:test123', $found->did);
		self::assertSame('test.bsky.social', $found->handle);
		self::assertSame('access_token_value', $found->accessToken);
	}

	public function testFindByDidReturnsNullForUnknownDid(): void
	{
		$store = new InMemorySessionStore();

		self::assertNull($store->findByDid('did:plc:unknown'));
	}

	public function testDeleteRemovesSession(): void
	{
		$store = new InMemorySessionStore();
		$session = $this->createSession();

		$store->save($session);
		$store->delete('did:plc:test123');

		self::assertNull($store->findByDid('did:plc:test123'));
	}

	public function testSaveWithSameDidOverwrites(): void
	{
		$store = new InMemorySessionStore();

		$session1 = $this->createSession();
		$store->save($session1);

		$session2 = new StoredSession(
			did: 'did:plc:test123',
			handle: 'updated.bsky.social',
			pdsUrl: 'https://pds.example.com',
			authServerIssuer: 'https://auth.example.com',
			tokenEndpoint: 'https://auth.example.com/token',
			accessToken: 'new_access_token',
			refreshToken: 'new_refresh_token',
			dpopPrivateKeyPem: 'fake-pem',
			expiresAt: new \DateTimeImmutable('+2 hours'),
			scope: 'atproto',
		);
		$store->save($session2);

		$found = $store->findByDid('did:plc:test123');
		self::assertNotNull($found);
		self::assertSame('updated.bsky.social', $found->handle);
		self::assertSame('new_access_token', $found->accessToken);
	}
}
