<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

use Gimucco\Atproto\Exception\ConfigurationException;

final class ClientConfig
{
	/**
	 * @param string $clientId The HTTPS URL where client metadata is hosted
	 * @param string $redirectUri OAuth callback URL
	 * @param string $scope Space-separated scopes (must include "atproto")
	 * @param string $clientName Human-readable application name
	 * @param string|null $clientUri Application homepage URL
	 * @param string|null $logoUri Application logo URL (HTTPS only)
	 * @param string|null $tosUri Terms of service URL
	 * @param string|null $policyUri Privacy policy URL
	 * @param string|null $jwksUri URL where the JWKS is hosted
	 * @param string|array<string, mixed> $privateKey ES256 private key in PEM format, or a JWK array
	 * @param string|null $encryptionPassphrase Passphrase for encrypting tokens at rest
	 *
	 * @throws ConfigurationException If the configuration is invalid
	 */
	public function __construct(
		public readonly string $clientId,
		public readonly string $redirectUri,
		public readonly string $scope,
		public readonly string $clientName,
		public readonly ?string $clientUri = null,
		public readonly ?string $logoUri = null,
		public readonly ?string $tosUri = null,
		public readonly ?string $policyUri = null,
		public readonly ?string $jwksUri = null,
		public readonly string|array $privateKey = '',
		public readonly ?string $encryptionPassphrase = null,
	) {
		$this->validate();
	}

	/**
	 * @throws ConfigurationException
	 */
	private function validate(): void
	{
		if (!str_starts_with($this->clientId, 'https://')) {
			throw new ConfigurationException('client_id must be an HTTPS URL');
		}

		if (!str_starts_with($this->redirectUri, 'https://') && !str_starts_with($this->redirectUri, 'http://localhost') && !str_starts_with($this->redirectUri, 'http://127.0.0.1')) {
			throw new ConfigurationException('redirect_uri must be an HTTPS URL (or localhost for development)');
		}

		if (!str_contains($this->scope, 'atproto')) {
			throw new ConfigurationException('scope must include "atproto"');
		}

		if ($this->clientName === '') {
			throw new ConfigurationException('client_name must not be empty');
		}

		if ($this->privateKey === '' || $this->privateKey === []) {
			throw new ConfigurationException('privateKey is required for confidential clients');
		}
	}
}
