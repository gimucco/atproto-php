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
	 * @param string $defaultAuthorizationServer Authorization server URL used by
	 *        `OAuthClient::beginAuthorization()` when called without a handle/DID
	 *        and without an explicit server. Defaults to `https://bsky.social`.
	 *        Override to point your "Sign in" button at a different atproto host
	 *        (e.g., a self-hosted PDS).
	 * @param list<string> $additionalRedirectUris Extra redirect URIs to declare in the
	 *        generated client metadata document. Use this when one client_id needs to
	 *        accept multiple callback URLs (e.g., a login flow and an account-linking
	 *        flow). Only consumed by `ClientMetadataBuilder`; at runtime this config
	 *        still uses `$redirectUri` for PAR and token exchange — declare a separate
	 *        `ClientConfig` instance per flow.
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
		public readonly string $defaultAuthorizationServer = 'https://bsky.social',
		public readonly array $additionalRedirectUris = [],
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

		if (!self::isValidRedirectUri($this->redirectUri)) {
			throw new ConfigurationException('redirect_uri must be an HTTPS URL (or localhost for development)');
		}

		foreach ($this->additionalRedirectUris as $uri) {
			if (!self::isValidRedirectUri($uri)) {
				throw new ConfigurationException('additionalRedirectUris entries must be HTTPS URLs (or localhost for development)');
			}
			if ($uri === $this->redirectUri) {
				throw new ConfigurationException('additionalRedirectUris must not duplicate the primary redirect_uri');
			}
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

		if (!str_starts_with($this->defaultAuthorizationServer, 'https://')) {
			throw new ConfigurationException('defaultAuthorizationServer must be an HTTPS URL');
		}
	}

	private static function isValidRedirectUri(string $uri): bool
	{
		return str_starts_with($uri, 'https://')
			|| str_starts_with($uri, 'http://localhost')
			|| str_starts_with($uri, 'http://127.0.0.1');
	}
}
