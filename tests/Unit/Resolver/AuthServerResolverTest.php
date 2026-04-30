<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Resolver;

use Gimucco\Atproto\Exception\ResolutionException;
use Gimucco\Atproto\Internal\Resolver\AuthServerResolver;
use Gimucco\Atproto\Tests\Integration\MockHttpClient;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class AuthServerResolverTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__.'/../../Integration/MockHttpClient.php';
	}

	public function testResolveDirectStripsTrailingSlash(): void
	{
		$mock = new MockHttpClient();
		$mock->addResponse($this->validMetadataResponse('https://example.com'));

		$resolver = new AuthServerResolver($mock, new HttpFactory());
		$meta = $resolver->resolveDirect('https://example.com/');

		self::assertSame('https://example.com', $meta['issuer_url']);
		self::assertSame(
			'https://example.com/.well-known/oauth-authorization-server',
			(string) $mock->sentRequests[0]->getUri(),
		);
	}

	public function testResolveDirectStripsQueryString(): void
	{
		$mock = new MockHttpClient();
		$mock->addResponse($this->validMetadataResponse('https://example.com'));

		$resolver = new AuthServerResolver($mock, new HttpFactory());
		$meta = $resolver->resolveDirect('https://example.com?foo=bar&baz=qux');

		self::assertSame('https://example.com', $meta['issuer_url']);
		self::assertSame(
			'https://example.com/.well-known/oauth-authorization-server',
			(string) $mock->sentRequests[0]->getUri(),
		);
	}

	public function testResolveDirectStripsFragment(): void
	{
		$mock = new MockHttpClient();
		$mock->addResponse($this->validMetadataResponse('https://example.com'));

		$resolver = new AuthServerResolver($mock, new HttpFactory());
		$meta = $resolver->resolveDirect('https://example.com#section');

		self::assertSame('https://example.com', $meta['issuer_url']);
		self::assertSame(
			'https://example.com/.well-known/oauth-authorization-server',
			(string) $mock->sentRequests[0]->getUri(),
		);
	}

	public function testResolveDirectPreservesPath(): void
	{
		// Per RFC 8414, an issuer can include a path. Discovery URL is constructed
		// by appending the well-known suffix.
		$mock = new MockHttpClient();
		$mock->addResponse($this->validMetadataResponse('https://example.com/auth'));

		$resolver = new AuthServerResolver($mock, new HttpFactory());
		$meta = $resolver->resolveDirect('https://example.com/auth/');

		self::assertSame('https://example.com/auth', $meta['issuer_url']);
		self::assertSame(
			'https://example.com/auth/.well-known/oauth-authorization-server',
			(string) $mock->sentRequests[0]->getUri(),
		);
	}

	public function testResolveDirectPreservesPort(): void
	{
		$mock = new MockHttpClient();
		$mock->addResponse($this->validMetadataResponse('https://example.com:8443'));

		$resolver = new AuthServerResolver($mock, new HttpFactory());
		$meta = $resolver->resolveDirect('https://example.com:8443');

		self::assertSame('https://example.com:8443', $meta['issuer_url']);
	}

	public function testResolveDirectRejectsInvalidUrl(): void
	{
		$mock = new MockHttpClient();
		$resolver = new AuthServerResolver($mock, new HttpFactory());

		$this->expectException(ResolutionException::class);
		$this->expectExceptionMessage('Invalid authorization server URL');

		$resolver->resolveDirect('not-a-url');
	}

	public function testResolveDirectRejectsMissingScheme(): void
	{
		$mock = new MockHttpClient();
		$resolver = new AuthServerResolver($mock, new HttpFactory());

		$this->expectException(ResolutionException::class);
		$this->expectExceptionMessage('Invalid authorization server URL');

		$resolver->resolveDirect('//example.com');
	}

	public function testResolveDirectRejectsNonHttpScheme(): void
	{
		$mock = new MockHttpClient();
		$resolver = new AuthServerResolver($mock, new HttpFactory());

		$this->expectException(ResolutionException::class);
		$this->expectExceptionMessage('must use http or https');

		$resolver->resolveDirect('ftp://example.com');
	}

	private function validMetadataResponse(string $issuer): Response
	{
		return new Response(200, ['Content-Type' => 'application/json'], json_encode([
			'issuer' => $issuer,
			'authorization_endpoint' => $issuer.'/authorize',
			'token_endpoint' => $issuer.'/token',
			'pushed_authorization_request_endpoint' => $issuer.'/par',
		], JSON_THROW_ON_ERROR));
	}
}
