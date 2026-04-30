<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

use Gimucco\Atproto\StateStoreInterface;

final class InMemoryStateStore implements StateStoreInterface
{
	/** @var array<string, array{data: array<string, mixed>, expires_at: int}> */
	private array $states = [];

	/**
	 * @param array<string, mixed> $data
	 */
	public function save(string $state, array $data, int $ttlSeconds): void
	{
		$this->states[$state] = [
			'data' => $data,
			'expires_at' => time() + $ttlSeconds,
		];
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function get(string $state): ?array
	{
		$entry = $this->states[$state] ?? null;
		if ($entry === null) {
			return null;
		}

		if ($entry['expires_at'] < time()) {
			unset($this->states[$state]);
			return null;
		}

		return $entry['data'];
	}

	public function delete(string $state): void
	{
		unset($this->states[$state]);
	}
}
