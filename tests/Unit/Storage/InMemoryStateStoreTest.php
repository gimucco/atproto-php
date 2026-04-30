<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage;

use Gimucco\Atproto\Storage\InMemoryStateStore;
use PHPUnit\Framework\TestCase;

final class InMemoryStateStoreTest extends TestCase
{
	public function testSaveThenGetReturnsData(): void
	{
		$store = new InMemoryStateStore();
		$data = ['verifier' => 'abc', 'did' => 'did:plc:test'];

		$store->save('state-key-1', $data, 300);

		self::assertSame($data, $store->get('state-key-1'));
	}

	public function testGetReturnsNullForUnknownState(): void
	{
		$store = new InMemoryStateStore();

		self::assertNull($store->get('nonexistent'));
	}

	public function testDeleteRemovesState(): void
	{
		$store = new InMemoryStateStore();
		$store->save('state-key-1', ['foo' => 'bar'], 300);

		$store->delete('state-key-1');

		self::assertNull($store->get('state-key-1'));
	}

	public function testExpiredStateReturnsNull(): void
	{
		$store = new InMemoryStateStore();

		// ttl=-1 means expires_at = time() - 1, which is already in the past
		$store->save('expired-state', ['foo' => 'bar'], -1);

		self::assertNull($store->get('expired-state'));
	}
}
