<?php

declare(strict_types=1);

namespace Gimucco\Atproto;

use Gimucco\Atproto\Internal\Jwt\KeyManager;

final class ClientMetadataBuilder
{
	/**
	 * Build the client metadata document to serve at the client_id URL.
	 *
	 * @param ClientConfig $config Client configuration
	 *
	 * @return array<string, mixed> The client metadata as an associative array (encode with json_encode)
	 */
	public static function fromConfig(ClientConfig $config): array
	{
		$metadata = [
			'client_id' => $config->clientId,
			'client_name' => $config->clientName,
			'application_type' => 'web',
			'grant_types' => ['authorization_code', 'refresh_token'],
			'response_types' => ['code'],
			'redirect_uris' => array_values(array_unique([$config->redirectUri, ...$config->additionalRedirectUris])),
			'scope' => $config->scope,
			'dpop_bound_access_tokens' => true,
			'token_endpoint_auth_method' => 'private_key_jwt',
			'token_endpoint_auth_signing_alg' => 'ES256',
		];

		if ($config->jwksUri !== null) {
			$metadata['jwks_uri'] = $config->jwksUri;
		} else {
			$metadata['jwks'] = self::jwksFromConfig($config);
		}

		if ($config->clientUri !== null) {
			$metadata['client_uri'] = $config->clientUri;
		}

		if ($config->logoUri !== null) {
			$metadata['logo_uri'] = $config->logoUri;
		}

		if ($config->tosUri !== null) {
			$metadata['tos_uri'] = $config->tosUri;
		}

		if ($config->policyUri !== null) {
			$metadata['policy_uri'] = $config->policyUri;
		}

		return $metadata;
	}

	/**
	 * Build the JWKS document containing the client's public key.
	 *
	 * @param ClientConfig $config Client configuration
	 *
	 * @return array{keys: array<int, array<string, mixed>>} The JWKS document
	 */
	public static function jwksFromConfig(ClientConfig $config): array
	{
		$jwk = KeyManager::privateKeyToJwk($config->privateKey);
		$publicArray = KeyManager::jwkToPublicArray($jwk);

		return [
			'keys' => [$publicArray],
		];
	}
}
