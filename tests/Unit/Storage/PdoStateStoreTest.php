<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage;

use Gimucco\Atproto\Storage\Pdo\Schema;
use Gimucco\Atproto\Storage\PdoStateStore;
use PHPUnit\Framework\TestCase;

final class PdoStateStoreTest extends TestCase
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

	public function testSaveThenGetReturnsData(): void
	{
		$store = new PdoStateStore($this->pdo);
		$data = ['verifier' => 'abc', 'did' => 'did:plc:test'];

		$store->save('state-key-1', $data, 300);

		self::assertSame($data, $store->get('state-key-1'));
	}

	public function testGetReturnsNullForUnknown(): void
	{
		$store = new PdoStateStore($this->pdo);

		self::assertNull($store->get('nonexistent'));
	}

	public function testExpiredStateReturnsNull(): void
	{
		$store = new PdoStateStore($this->pdo);

		// ttl=-1 means expires_at = time() - 1, already expired
		$store->save('expired-state', ['foo' => 'bar'], -1);

		self::assertNull($store->get('expired-state'));
	}

	public function testDeleteRemovesState(): void
	{
		$store = new PdoStateStore($this->pdo);
		$store->save('state-key-1', ['foo' => 'bar'], 300);

		$store->delete('state-key-1');

		self::assertNull($store->get('state-key-1'));
	}
}
