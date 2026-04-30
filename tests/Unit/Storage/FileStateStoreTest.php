<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage;

use Gimucco\Atproto\Storage\FileStateStore;
use PHPUnit\Framework\TestCase;

final class FileStateStoreTest extends TestCase
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

	public function testSaveThenGetReturnsData(): void
	{
		$store = new FileStateStore($this->directory);
		$data = ['verifier' => 'abc', 'did' => 'did:plc:test'];

		$store->save('state-key-1', $data, 300);

		self::assertSame($data, $store->get('state-key-1'));
	}

	public function testExpiredStateReturnsNull(): void
	{
		$store = new FileStateStore($this->directory);

		// ttl=-1 means expires_at = time() - 1, already expired
		$store->save('expired-state', ['foo' => 'bar'], -1);

		self::assertNull($store->get('expired-state'));
	}

	public function testDeleteRemovesState(): void
	{
		$store = new FileStateStore($this->directory);
		$store->save('state-key-1', ['foo' => 'bar'], 300);

		$store->delete('state-key-1');

		self::assertNull($store->get('state-key-1'));
	}

	public function testGetReturnsNullForUnknown(): void
	{
		$store = new FileStateStore($this->directory);

		self::assertNull($store->get('nonexistent'));
	}

	public function testWithEncryptionRoundTrips(): void
	{
		$store = new FileStateStore($this->directory, passphrase: 'test-passphrase');
		$data = ['verifier' => 'abc', 'secret' => 'sensitive-data'];

		$store->save('encrypted-state', $data, 300);

		self::assertSame($data, $store->get('encrypted-state'));
	}
}
