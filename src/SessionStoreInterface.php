<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

interface SessionStoreInterface
{
	/**
	 * @param StoredSession $session The session to persist
	 *
	 * @throws Exception\SessionException If the session cannot be saved
	 */
	public function save(StoredSession $session): void;

	/**
	 * @param string $did The DID to look up
	 *
	 * @return StoredSession|null The stored session, or null if not found
	 */
	public function findByDid(string $did): ?StoredSession;

	/**
	 * @param string $did The DID whose session should be removed
	 *
	 * @throws Exception\SessionException If the session cannot be deleted
	 */
	public function delete(string $did): void;
}
