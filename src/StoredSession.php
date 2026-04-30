<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

final class StoredSession
{
	/**
	 * @param string $did The user's DID (e.g., did:plc:xxx)
	 * @param string $handle The user's handle (e.g., alice.bsky.social)
	 * @param string $pdsUrl The user's PDS URL
	 * @param string $authServerIssuer The authorization server issuer URL
	 * @param string $tokenEndpoint The authorization server token endpoint
	 * @param string $accessToken The current access token
	 * @param string $refreshToken The current refresh token
	 * @param string $dpopPrivateKeyPem The session DPoP private key in PEM format
	 * @param \DateTimeImmutable $expiresAt When the access token expires
	 * @param string $scope The granted scope
	 */
	public function __construct(
		public readonly string $did,
		public readonly string $handle,
		public readonly string $pdsUrl,
		public readonly string $authServerIssuer,
		public readonly string $tokenEndpoint,
		public string $accessToken,
		public string $refreshToken,
		public readonly string $dpopPrivateKeyPem,
		public \DateTimeImmutable $expiresAt,
		public readonly string $scope,
	) {}

	public function isExpired(): bool
	{
		return $this->expiresAt <= new \DateTimeImmutable();
	}

	public function isNearExpiry(int $bufferSeconds = 60): bool
	{
		$buffer = new \DateTimeImmutable('+'.$bufferSeconds.' seconds');

		return $this->expiresAt <= $buffer;
	}

	/**
	 * @return array<string, string|int>
	 */
	public function toArray(): array
	{
		return [
			'did' => $this->did,
			'handle' => $this->handle,
			'pds_url' => $this->pdsUrl,
			'auth_server_issuer' => $this->authServerIssuer,
			'token_endpoint' => $this->tokenEndpoint,
			'access_token' => $this->accessToken,
			'refresh_token' => $this->refreshToken,
			'dpop_private_key_pem' => $this->dpopPrivateKeyPem,
			'expires_at' => $this->expiresAt->getTimestamp(),
			'scope' => $this->scope,
		];
	}

	/**
	 * @param array<string, mixed> $data
	 *
	 * @throws \InvalidArgumentException If required fields are missing
	 */
	public static function fromArray(array $data): self
	{
		return new self(
			did: (string) ($data['did'] ?? ''),
			handle: (string) ($data['handle'] ?? ''),
			pdsUrl: (string) ($data['pds_url'] ?? ''),
			authServerIssuer: (string) ($data['auth_server_issuer'] ?? ''),
			tokenEndpoint: (string) ($data['token_endpoint'] ?? ''),
			accessToken: (string) ($data['access_token'] ?? ''),
			refreshToken: (string) ($data['refresh_token'] ?? ''),
			dpopPrivateKeyPem: (string) ($data['dpop_private_key_pem'] ?? ''),
			expiresAt: (new \DateTimeImmutable())->setTimestamp((int) ($data['expires_at'] ?? 0)),
			scope: (string) ($data['scope'] ?? ''),
		);
	}
}
