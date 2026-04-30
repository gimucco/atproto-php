<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

use Gimucco\Atproto\Exception\SessionException;
use Gimucco\Atproto\StateStoreInterface;

final class FileStateStore implements StateStoreInterface
{
	private readonly ?EncryptionHelper $encryption;

	/**
	 * @param string $directory Directory to store state files
	 * @param string|null $passphrase Passphrase for encrypting state data at rest
	 *
	 * @throws SessionException If the directory cannot be created
	 */
	public function __construct(
		private readonly string $directory,
		?string $passphrase = null,
	) {
		if (!is_dir($this->directory) && !mkdir($this->directory, 0o700, true)) {
			throw new SessionException('Cannot create state storage directory: '.$this->directory);
		}

		$this->encryption = ($passphrase !== null && $passphrase !== '')
			? new EncryptionHelper($passphrase)
			: null;
	}

	/**
	 * @param array<string, mixed> $data
	 */
	public function save(string $state, array $data, int $ttlSeconds): void
	{
		$payload = json_encode([
			'data' => $data,
			'expires_at' => time() + $ttlSeconds,
		], JSON_THROW_ON_ERROR);

		if ($this->encryption !== null) {
			$payload = $this->encryption->encrypt($payload);
		}

		$path = $this->pathForState($state);
		if (file_put_contents($path, $payload, LOCK_EX) === false) {
			throw new SessionException('Failed to write state file: '.$path);
		}
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function get(string $state): ?array
	{
		$path = $this->pathForState($state);
		if (!file_exists($path)) {
			return null;
		}

		$contents = file_get_contents($path);
		if ($contents === false) {
			return null;
		}

		if ($this->encryption !== null) {
			$decrypted = $this->encryption->decrypt($contents);
			if ($decrypted === null) {
				return null;
			}
			$contents = $decrypted;
		}

		/** @var array{data: array<string, mixed>, expires_at: int}|null $payload */
		$payload = json_decode($contents, true);
		if (!\is_array($payload)) {
			return null;
		}

		if ($payload['expires_at'] < time()) {
			$this->delete($state);
			return null;
		}

		/** @var array<string, mixed> */
		return $payload['data'];
	}

	public function delete(string $state): void
	{
		$path = $this->pathForState($state);
		if (file_exists($path)) {
			unlink($path);
		}
	}

	private function pathForState(string $state): string
	{
		return $this->directory.'/'.hash('sha256', $state).'.state.json';
	}
}
