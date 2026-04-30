<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Jwt;

use Gimucco\Atproto\Exception\ConfigurationException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * @internal
 */
final class KeyManager
{
	private readonly JWSBuilder $jwsBuilder;
	private readonly CompactSerializer $serializer;

	public function __construct()
	{
		$algorithmManager = new AlgorithmManager([new ES256()]);
		$this->jwsBuilder = new JWSBuilder($algorithmManager);
		$this->serializer = new CompactSerializer();
	}

	/**
	 * @param array<string, mixed> $header
	 * @param array<string, mixed> $payload
	 *
	 * @throws \RuntimeException
	 */
	public function sign(array $header, array $payload, JWK $key): string
	{
		$payloadJson = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

		$jws = $this->jwsBuilder
			->create()
			->withPayload($payloadJson)
			->addSignature($key, $header)
			->build();

		return $this->serializer->serialize($jws, 0);
	}

	/**
	 * @param string|array<string, mixed> $privateKey PEM string or JWK array
	 *
	 * @throws ConfigurationException
	 */
	public static function privateKeyToJwk(string|array $privateKey): JWK
	{
		if (\is_array($privateKey)) {
			$jwk = new JWK($privateKey);
		} else {
			$key = openssl_pkey_get_private($privateKey);
			if ($key === false) {
				throw new ConfigurationException('Invalid private key PEM');
			}

			$details = openssl_pkey_get_details($key);
			if ($details === false || ($details['type'] ?? -1) !== OPENSSL_KEYTYPE_EC) {
				throw new ConfigurationException('Private key must be an EC key (P-256)');
			}

			/** @var array{x: string, y: string, d: string} $ec */
			$ec = $details['ec'];

			$jwk = new JWK([
				'kty' => 'EC',
				'crv' => 'P-256',
				'x' => self::base64url(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)),
				'y' => self::base64url(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)),
				'd' => self::base64url(str_pad($ec['d'], 32, "\0", STR_PAD_LEFT)),
			]);
		}

		if (!$jwk->has('kid')) {
			$jwk = self::withDerivedKid($jwk);
		}

		return $jwk;
	}

	/**
	 * Compute the RFC 7638 JWK thumbprint and attach it as `kid`.
	 *
	 * The thumbprint is deterministic from the public key components, so the
	 * same kid is produced for the matching public/private pair — letting an
	 * auth server unambiguously map a signed JWT to a JWKS entry.
	 */
	private static function withDerivedKid(JWK $jwk): JWK
	{
		$kid = $jwk->thumbprint('sha256');
		$values = $jwk->all();
		$values['kid'] = $kid;

		return new JWK($values);
	}

	public static function publicJwk(JWK $privateKey): JWK
	{
		return $privateKey->toPublic();
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function jwkToPublicArray(JWK $jwk): array
	{
		$public = $jwk->toPublic();

		return array_filter([
			'kty' => $public->get('kty'),
			'crv' => $public->get('crv'),
			'x' => $public->get('x'),
			'y' => $public->get('y'),
			'kid' => $public->has('kid') ? $public->get('kid') : null,
			'use' => 'sig',
			'alg' => 'ES256',
		], static fn(mixed $v): bool => $v !== null);
	}

	public static function generateDpopKeyPem(): string
	{
		$key = openssl_pkey_new([
			'curve_name' => 'prime256v1',
			'private_key_type' => OPENSSL_KEYTYPE_EC,
		]);

		if ($key === false) {
			throw new \RuntimeException('Failed to generate EC key pair');
		}

		$pem = '';
		openssl_pkey_export($key, $pem);

		return $pem;
	}

	/**
	 * @return array<string, string>
	 */
	public static function pemToJwkArray(string $pem): array
	{
		$key = openssl_pkey_get_private($pem);
		if ($key === false) {
			throw new ConfigurationException('Invalid PEM key');
		}

		$details = openssl_pkey_get_details($key);
		if ($details === false) {
			throw new ConfigurationException('Failed to extract key details');
		}

		/** @var array{x: string, y: string, d: string} $ec */
		$ec = $details['ec'];

		return [
			'kty' => 'EC',
			'crv' => 'P-256',
			'x' => self::base64url(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)),
			'y' => self::base64url(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)),
			'd' => self::base64url(str_pad($ec['d'], 32, "\0", STR_PAD_LEFT)),
		];
	}

	private static function base64url(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
