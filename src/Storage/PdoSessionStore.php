<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\SessionStoreInterface;
use Gimucco\Atproto\StoredSession;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class PdoSessionStore implements SessionStoreInterface
{
	private readonly ?EncryptionHelper $encryption;

	/**
	 * @param \PDO $pdo Database connection
	 * @param string $tableName Table name for sessions
	 * @param string|null $passphrase Passphrase for encrypting sensitive fields at rest
	 * @param LoggerInterface $logger Logger for warnings
	 */
	public function __construct(
		private readonly \PDO $pdo,
		private readonly string $tableName = 'atproto_sessions',
		?string $passphrase = null,
		private readonly LoggerInterface $logger = new NullLogger(),
	) {
		if ($passphrase !== null && $passphrase !== '') {
			$this->encryption = new EncryptionHelper($passphrase);
		} else {
			$this->encryption = null;
			$this->logger->warning('PdoSessionStore: no encryption passphrase provided — tokens stored in plaintext');
		}
	}

	public function save(StoredSession $session): void
	{
		$data = $session->toArray();

		$accessToken = (string) $data['access_token'];
		$refreshToken = (string) $data['refresh_token'];
		$dpopKey = (string) $data['dpop_private_key_pem'];

		if ($this->encryption !== null) {
			$accessToken = $this->encryption->encrypt($accessToken);
			$refreshToken = $this->encryption->encrypt($refreshToken);
			$dpopKey = $this->encryption->encrypt($dpopKey);
		}

		$sql = <<<SQL
            INSERT INTO {$this->tableName} (did, handle, pds_url, auth_server_issuer, token_endpoint, access_token, refresh_token, dpop_private_key_pem, expires_at, scope)
            VALUES (:did, :handle, :pds_url, :auth_server_issuer, :token_endpoint, :access_token, :refresh_token, :dpop_private_key_pem, :expires_at, :scope)
            ON CONFLICT (did) DO UPDATE SET
                handle = :handle,
                pds_url = :pds_url,
                auth_server_issuer = :auth_server_issuer,
                token_endpoint = :token_endpoint,
                access_token = :access_token,
                refresh_token = :refresh_token,
                dpop_private_key_pem = :dpop_private_key_pem,
                expires_at = :expires_at,
                scope = :scope
            SQL;

		try {
			$stmt = $this->pdo->prepare($sql);
			$stmt->execute([
				':did' => $data['did'],
				':handle' => $data['handle'],
				':pds_url' => $data['pds_url'],
				':auth_server_issuer' => $data['auth_server_issuer'],
				':token_endpoint' => $data['token_endpoint'],
				':access_token' => $accessToken,
				':refresh_token' => $refreshToken,
				':dpop_private_key_pem' => $dpopKey,
				':expires_at' => $data['expires_at'],
				':scope' => $data['scope'],
			]);
		} catch (\PDOException $e) {
			throw new SessionException('Failed to save session: '.$e->getMessage(), 0, $e);
		}
	}

	public function findByDid(string $did): ?StoredSession
	{
		try {
			$stmt = $this->pdo->prepare("SELECT * FROM {$this->tableName} WHERE did = :did LIMIT 1");
			$stmt->execute([':did' => $did]);

			/** @var array<string, mixed>|false $row */
			$row = $stmt->fetch(\PDO::FETCH_ASSOC);
		} catch (\PDOException $e) {
			throw new SessionException('Failed to find session: '.$e->getMessage(), 0, $e);
		}

		if ($row === false) {
			return null;
		}

		if ($this->encryption !== null) {
			foreach (['access_token', 'refresh_token', 'dpop_private_key_pem'] as $field) {
				if (isset($row[$field]) && \is_string($row[$field]) && $row[$field] !== '') {
					$decrypted = $this->encryption->decrypt($row[$field]);
					if ($decrypted === null) {
						throw new SessionException('Failed to decrypt session field: '.$field);
					}
					$row[$field] = $decrypted;
				}
			}
		}

		return StoredSession::fromArray($row);
	}

	public function delete(string $did): void
	{
		try {
			$stmt = $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE did = :did");
			$stmt->execute([':did' => $did]);
		} catch (\PDOException $e) {
			throw new SessionException('Failed to delete session: '.$e->getMessage(), 0, $e);
		}
	}
}
