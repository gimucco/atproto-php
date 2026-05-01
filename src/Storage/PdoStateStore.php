<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\StateStoreInterface;
use Gimucco\Atproto\Storage\Pdo\UpsertSqlBuilder;

final class PdoStateStore implements StateStoreInterface
{
	private readonly ?EncryptionHelper $encryption;
	private readonly string $driver;

	/**
	 * @param \PDO $pdo Database connection
	 * @param string $tableName Table name for state entries
	 * @param string|null $passphrase Passphrase for encrypting state data at rest
	 */
	public function __construct(
		private readonly \PDO $pdo,
		private readonly string $tableName = 'atproto_oauth_states',
		?string $passphrase = null,
	) {
		$this->encryption = ($passphrase !== null && $passphrase !== '')
			? new EncryptionHelper($passphrase)
			: null;
		$this->driver = (string) $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
	}

	/**
	 * @param array<string, mixed> $data
	 */
	public function save(string $state, array $data, int $ttlSeconds): void
	{
		$payload = json_encode($data, JSON_THROW_ON_ERROR);

		if ($this->encryption !== null) {
			$payload = $this->encryption->encrypt($payload);
		}

		$sql = UpsertSqlBuilder::build(
			driver: $this->driver,
			table: $this->tableName,
			insertColumns: ['state_key', 'payload', 'expires_at'],
			conflictColumn: 'state_key',
			updateColumns: ['payload', 'expires_at'],
		);

		try {
			$stmt = $this->pdo->prepare($sql);
			$stmt->execute([
				':state_key' => $state,
				':payload' => $payload,
				':expires_at' => time() + $ttlSeconds,
			]);
		} catch (\PDOException $e) {
			throw new SessionException('Failed to save state: '.$e->getMessage(), 0, $e);
		}
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function get(string $state): ?array
	{
		try {
			$stmt = $this->pdo->prepare(
				"SELECT payload, expires_at FROM {$this->tableName} WHERE state_key = :state_key LIMIT 1",
			);
			$stmt->execute([':state_key' => $state]);

			/** @var array{payload: string, expires_at: int|string}|false $row */
			$row = $stmt->fetch(\PDO::FETCH_ASSOC);
		} catch (\PDOException $e) {
			throw new SessionException('Failed to get state: '.$e->getMessage(), 0, $e);
		}

		if ($row === false) {
			return null;
		}

		if ((int) $row['expires_at'] < time()) {
			$this->delete($state);
			return null;
		}

		$payload = $row['payload'];

		if ($this->encryption !== null) {
			$decrypted = $this->encryption->decrypt($payload);
			if ($decrypted === null) {
				return null;
			}
			$payload = $decrypted;
		}

		/** @var array<string, mixed>|null */
		return json_decode($payload, true);
	}

	public function delete(string $state): void
	{
		try {
			$stmt = $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE state_key = :state_key");
			$stmt->execute([':state_key' => $state]);
		} catch (\PDOException $e) {
			throw new SessionException('Failed to delete state: '.$e->getMessage(), 0, $e);
		}
	}
}
