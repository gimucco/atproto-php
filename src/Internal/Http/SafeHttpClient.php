<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Internal\Http;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * PSR-18 client wrapper that validates request URLs against an SsrfGuard
 * before delegating to the underlying client.
 *
 * @internal
 */
final class SafeHttpClient implements ClientInterface
{
	public function __construct(
		private readonly ClientInterface $inner,
		private readonly SsrfGuard $guard,
	) {}

	public function sendRequest(RequestInterface $request): ResponseInterface
	{
		$this->guard->validate((string) $request->getUri());

		return $this->inner->sendRequest($request);
	}
}
