<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Integration;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A queue-based mock PSR-18 HTTP client for integration tests.
 *
 * Responses are returned in FIFO order. All sent requests are recorded
 * for later assertion.
 */
final class MockHttpClient implements ClientInterface
{
	/** @var ResponseInterface[] */
	private array $responses = [];

	/** @var RequestInterface[] */
	public array $sentRequests = [];

	private int $responseIndex = 0;

	public function addResponse(ResponseInterface $response): void
	{
		$this->responses[] = $response;
	}

	public function sendRequest(RequestInterface $request): ResponseInterface
	{
		$this->sentRequests[] = $request;

		if (!isset($this->responses[$this->responseIndex])) {
			throw new \RuntimeException(
				'No more mocked responses (request #'.$this->responseIndex
				.' '.$request->getMethod().' '.$request->getUri().')',
			);
		}

		return $this->responses[$this->responseIndex++];
	}

	public function getRequestCount(): int
	{
		return \count($this->sentRequests);
	}
}
