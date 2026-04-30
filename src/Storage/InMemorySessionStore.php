<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

use Gimucco\Atproto\SessionStoreInterface;
use Gimucco\Atproto\StoredSession;

final class InMemorySessionStore implements SessionStoreInterface
{
	/** @var array<string, StoredSession> */
	private array $sessions = [];

	public function save(StoredSession $session): void
	{
		$this->sessions[$session->did] = $session;
	}

	public function findByDid(string $did): ?StoredSession
	{
		return $this->sessions[$did] ?? null;
	}

	public function delete(string $did): void
	{
		unset($this->sessions[$did]);
	}
}
