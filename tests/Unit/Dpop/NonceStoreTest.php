<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Dpop;

use Gimucco\Atproto\Internal\Dpop\NonceStore;
use PHPUnit\Framework\TestCase;

final class NonceStoreTest extends TestCase
{
	public function testGetReturnsNullForUnknownUrl(): void
	{
		$store = new NonceStore();

		self::assertNull($store->get('https://unknown.example.com/token'));
	}

	public function testSetThenGetReturnsTheNonce(): void
	{
		$store = new NonceStore();

		$store->set('https://auth.example.com/token', 'nonce-abc');

		self::assertSame('nonce-abc', $store->get('https://auth.example.com/token'));
	}

	public function testSameOriginDifferentPathsShareNonce(): void
	{
		$store = new NonceStore();

		$store->set('https://auth.example.com/token', 'shared-nonce');

		self::assertSame('shared-nonce', $store->get('https://auth.example.com/par'));
		self::assertSame('shared-nonce', $store->get('https://auth.example.com/other/path'));
	}

	public function testDifferentOriginsHaveIndependentNonces(): void
	{
		$store = new NonceStore();

		$store->set('https://auth.example.com/token', 'nonce-a');
		$store->set('https://pds.example.com/xrpc', 'nonce-b');

		self::assertSame('nonce-a', $store->get('https://auth.example.com/token'));
		self::assertSame('nonce-b', $store->get('https://pds.example.com/xrpc'));
	}
}
