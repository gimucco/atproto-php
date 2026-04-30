<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

interface StateStoreInterface
{
	/**
	 * @param string $state The unique state key
	 * @param array<string, mixed> $data The data to store
	 * @param int $ttlSeconds Time-to-live in seconds
	 *
	 * @throws Exception\SessionException If the state cannot be saved
	 */
	public function save(string $state, array $data, int $ttlSeconds): void;

	/**
	 * @param string $state The state key to look up
	 *
	 * @return array<string, mixed>|null The stored data, or null if not found or expired
	 */
	public function get(string $state): ?array;

	/**
	 * @param string $state The state key to remove
	 */
	public function delete(string $state): void;
}
