<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Http;

use Gimucco\Atproto\Exception\DpopException;
use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Exception\TokenException;
use Gimucco\Atproto\Internal\Dpop\DpopProofGenerator;
use Gimucco\Atproto\Internal\Dpop\NonceStore;
use Jose\Component\Core\JWK;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Wraps a PSR-18 HTTP client with DPoP nonce retry logic.
 *
 * Portions of this file are adapted from Automattic/wordpress-atmosphere
 * (https://github.com/Automattic/wordpress-atmosphere), licensed under
 * GPL-2.0-or-later. Original copyright Automattic Inc.
 *
 * @internal
 */
final class OAuthHttpClient
{
	private readonly DpopProofGenerator $dpopGenerator;

	public function __construct(
		private readonly ClientInterface $httpClient,
		private readonly RequestFactoryInterface $requestFactory,
		private readonly StreamFactoryInterface $streamFactory,
		private readonly NonceStore $nonceStore,
		private readonly LoggerInterface $logger = new NullLogger(),
	) {
		$this->dpopGenerator = new DpopProofGenerator();
	}

	/**
	 * Send a token/PAR endpoint request with DPoP and automatic nonce retry.
	 *
	 * @param string $url The endpoint URL
	 * @param array<string, string> $body Form-encoded body parameters
	 * @param JWK $dpopKey The DPoP session key
	 * @param string|null $accessToken Access token for ath claim (null for token requests)
	 *
	 * @return ResponseInterface The successful response
	 *
	 * @throws TokenException On token endpoint errors
	 * @throws DpopException On DPoP failures
	 * @throws NetworkException On transport failures
	 */
	public function sendTokenRequest(
		string $url,
		array $body,
		JWK $dpopKey,
		?string $accessToken = null,
	): ResponseInterface {
		$nonce = $this->nonceStore->get($url);
		$dpopProof = $this->dpopGenerator->generate($dpopKey, 'POST', $url, $nonce, $accessToken);

		$request = $this->requestFactory->createRequest('POST', $url)
			->withHeader('Content-Type', 'application/x-www-form-urlencoded')
			->withHeader('DPoP', $dpopProof)
			->withBody($this->streamFactory->createStream(http_build_query($body)));

		try {
			$response = $this->httpClient->sendRequest($request);
		} catch (ClientExceptionInterface $e) {
			throw new NetworkException('HTTP request failed: '.$e->getMessage(), 0, $e);
		}

		$this->captureNonce($response, $url);

		if ($this->isDpopNonceError($response)) {
			$this->logger->debug('DPoP nonce required, retrying with server nonce', ['url' => $url]);

			$nonce = $this->nonceStore->get($url);
			if ($nonce === null) {
				throw new DpopException('Server requested DPoP nonce but did not provide one');
			}

			$dpopProof = $this->dpopGenerator->generate($dpopKey, 'POST', $url, $nonce, $accessToken);

			$request = $this->requestFactory->createRequest('POST', $url)
				->withHeader('Content-Type', 'application/x-www-form-urlencoded')
				->withHeader('DPoP', $dpopProof)
				->withBody($this->streamFactory->createStream(http_build_query($body)));

			try {
				$response = $this->httpClient->sendRequest($request);
			} catch (ClientExceptionInterface $e) {
				throw new NetworkException('HTTP request failed on DPoP retry: '.$e->getMessage(), 0, $e);
			}

			$this->captureNonce($response, $url);
		}

		$this->logErrorResponse($response, $url);

		return $response;
	}

	/**
	 * Send an authenticated resource request with DPoP and nonce retry.
	 *
	 * @param string $method HTTP method
	 * @param string $url The resource URL
	 * @param string $accessToken The access token
	 * @param JWK $dpopKey The DPoP session key
	 * @param array<string, string> $headers Additional headers
	 * @param string $body Request body
	 *
	 * @return ResponseInterface
	 *
	 * @throws DpopException
	 * @throws NetworkException
	 */
	public function sendResourceRequest(
		string $method,
		string $url,
		string $accessToken,
		JWK $dpopKey,
		array $headers = [],
		string $body = '',
	): ResponseInterface {
		$nonce = $this->nonceStore->get($url);
		$dpopProof = $this->dpopGenerator->generate($dpopKey, $method, $url, $nonce, $accessToken);

		$request = $this->requestFactory->createRequest($method, $url)
			->withHeader('Authorization', 'DPoP '.$accessToken)
			->withHeader('DPoP', $dpopProof);

		foreach ($headers as $name => $value) {
			$request = $request->withHeader($name, $value);
		}

		if ($body !== '') {
			$request = $request->withBody($this->streamFactory->createStream($body));
		}

		try {
			$response = $this->httpClient->sendRequest($request);
		} catch (ClientExceptionInterface $e) {
			throw new NetworkException('HTTP request failed: '.$e->getMessage(), 0, $e);
		}

		$this->captureNonce($response, $url);

		if ($this->isResourceDpopNonceError($response)) {
			$this->logger->debug('DPoP nonce required for resource request, retrying', ['url' => $url]);

			$nonce = $this->nonceStore->get($url);
			if ($nonce === null) {
				throw new DpopException('Server requested DPoP nonce but did not provide one');
			}

			$dpopProof = $this->dpopGenerator->generate($dpopKey, $method, $url, $nonce, $accessToken);

			$request = $this->requestFactory->createRequest($method, $url)
				->withHeader('Authorization', 'DPoP '.$accessToken)
				->withHeader('DPoP', $dpopProof);

			foreach ($headers as $name => $value) {
				$request = $request->withHeader($name, $value);
			}

			if ($body !== '') {
				$request = $request->withBody($this->streamFactory->createStream($body));
			}

			try {
				$response = $this->httpClient->sendRequest($request);
			} catch (ClientExceptionInterface $e) {
				throw new NetworkException('HTTP request failed on DPoP retry: '.$e->getMessage(), 0, $e);
			}

			$this->captureNonce($response, $url);
		}

		return $response;
	}

	/**
	 * Log full response detail (status, body, headers) when the auth server
	 * returns an error. Helps debugging client_assertion / DPoP failures.
	 */
	private function logErrorResponse(ResponseInterface $response, string $url): void
	{
		$status = $response->getStatusCode();
		if ($status < 400) {
			return;
		}

		$body = (string) $response->getBody();
		$response->getBody()->rewind();

		$this->logger->error('Auth server returned error', [
			'url' => $url,
			'status' => $status,
			'body' => $body,
			'www_authenticate' => $response->getHeaderLine('WWW-Authenticate'),
			'content_type' => $response->getHeaderLine('Content-Type'),
		]);
	}

	private function captureNonce(ResponseInterface $response, string $url): void
	{
		$nonce = $response->getHeaderLine('DPoP-Nonce');
		if ($nonce !== '') {
			$this->nonceStore->set($url, $nonce);
		}
	}

	private function isDpopNonceError(ResponseInterface $response): bool
	{
		$status = $response->getStatusCode();
		if ($status !== 400 && $status !== 401) {
			return false;
		}

		/** @var array{error?: string}|null $data */
		$data = json_decode((string) $response->getBody(), true);

		return ($data['error'] ?? '') === 'use_dpop_nonce';
	}

	private function isResourceDpopNonceError(ResponseInterface $response): bool
	{
		if ($response->getStatusCode() !== 401) {
			return false;
		}

		$wwwAuth = $response->getHeaderLine('WWW-Authenticate');

		return str_contains($wwwAuth, 'use_dpop_nonce');
	}
}
