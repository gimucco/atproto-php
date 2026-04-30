<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\SessionStoreInterface;
use Gimucco\Atproto\StoredSession;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class FileSessionStore implements SessionStoreInterface
{
	private readonly ?EncryptionHelper $encryption;

	/**
	 * @param string $directory Directory to store session files
	 * @param string|null $passphrase Passphrase for encrypting sensitive fields at rest
	 * @param LoggerInterface $logger Logger for warnings
	 *
	 * @throws SessionException If the directory cannot be created
	 */
	public function __construct(
		private readonly string $directory,
		?string $passphrase = null,
		private readonly LoggerInterface $logger = new NullLogger(),
	) {
		if (!is_dir($this->directory) && !mkdir($this->directory, 0o700, true)) {
			throw new SessionException('Cannot create session storage directory: '.$this->directory);
		}

		if ($passphrase !== null && $passphrase !== '') {
			$this->encryption = new EncryptionHelper($passphrase);
		} else {
			$this->encryption = null;
			$this->logger->warning('FileSessionStore: no encryption passphrase provided — tokens stored in plaintext');
		}
	}

	public function save(StoredSession $session): void
	{
		$data = $session->toArray();
		$data = $this->encryptSensitiveFields($data);

		$path = $this->pathForDid($session->did);
		$json = json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);

		if (file_put_contents($path, $json, LOCK_EX) === false) {
			throw new SessionException('Failed to write session file: '.$path);
		}
	}

	public function findByDid(string $did): ?StoredSession
	{
		$path = $this->pathForDid($did);
		if (!file_exists($path)) {
			return null;
		}

		$contents = file_get_contents($path);
		if ($contents === false) {
			return null;
		}

		/** @var array<string, mixed>|null $data */
		$data = json_decode($contents, true);
		if (!\is_array($data)) {
			return null;
		}

		$data = $this->decryptSensitiveFields($data);

		return StoredSession::fromArray($data);
	}

	public function delete(string $did): void
	{
		$path = $this->pathForDid($did);
		if (file_exists($path)) {
			unlink($path);
		}
	}

	private function pathForDid(string $did): string
	{
		return $this->directory.'/'.hash('sha256', $did).'.json';
	}

	/**
	 * @param array<string, mixed> $data
	 *
	 * @return array<string, mixed>
	 */
	private function encryptSensitiveFields(array $data): array
	{
		if ($this->encryption === null) {
			return $data;
		}

		foreach (['access_token', 'refresh_token', 'dpop_private_key_pem'] as $field) {
			if (isset($data[$field]) && \is_string($data[$field]) && $data[$field] !== '') {
				$data[$field] = $this->encryption->encrypt($data[$field]);
			}
		}
		$data['encrypted'] = true;

		return $data;
	}

	/**
	 * @param array<string, mixed> $data
	 *
	 * @return array<string, mixed>
	 */
	private function decryptSensitiveFields(array $data): array
	{
		if ($this->encryption === null || !($data['encrypted'] ?? false)) {
			return $data;
		}

		foreach (['access_token', 'refresh_token', 'dpop_private_key_pem'] as $field) {
			if (isset($data[$field]) && \is_string($data[$field]) && $data[$field] !== '') {
				$decrypted = $this->encryption->decrypt($data[$field]);
				if ($decrypted === null) {
					throw new SessionException('Failed to decrypt field: '.$field);
				}
				$data[$field] = $decrypted;
			}
		}

		unset($data['encrypted']);

		return $data;
	}
}
