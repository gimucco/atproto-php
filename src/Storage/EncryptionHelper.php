<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage;

/**
 * Symmetric encryption at rest via libsodium.
 *
 * Portions of this file are adapted from Automattic/wordpress-atmosphere
 * (https://github.com/Automattic/wordpress-atmosphere), licensed under
 * GPL-2.0-or-later. Original copyright Automattic Inc.
 *
 * @internal
 */
final class EncryptionHelper
{
	private readonly string $key;

	public function __construct(string $passphrase)
	{
		$this->key = sodium_crypto_generichash(
			$passphrase,
			'',
			SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
		);
	}

	public function encrypt(string $plaintext): string
	{
		$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $this->key);

		return base64_encode($nonce.$ciphertext);
	}

	public function decrypt(string $encoded): ?string
	{
		$raw = base64_decode($encoded, true);
		if ($raw === false) {
			return null;
		}

		$nonceLen = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
		if (\strlen($raw) < $nonceLen + 1) {
			return null;
		}

		$result = sodium_crypto_secretbox_open(
			substr($raw, $nonceLen),
			substr($raw, 0, $nonceLen),
			$this->key,
		);

		return $result === false ? null : $result;
	}
}
