<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Http;

use Gimucco\Atproto\Exception\NetworkException;
use Gimucco\Atproto\Internal\Http\SsrfGuard;
use PHPUnit\Framework\TestCase;

final class SsrfGuardTest extends TestCase
{
	public function testIsPublicIpAcceptsPublicIPv4(): void
	{
		self::assertTrue(SsrfGuard::isPublicIp('8.8.8.8'));
		self::assertTrue(SsrfGuard::isPublicIp('1.1.1.1'));
		self::assertTrue(SsrfGuard::isPublicIp('151.101.1.69'));
	}

	public function testIsPublicIpRejectsPrivateIPv4(): void
	{
		self::assertFalse(SsrfGuard::isPublicIp('10.0.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('10.255.255.255'));
		self::assertFalse(SsrfGuard::isPublicIp('172.16.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('172.31.255.254'));
		self::assertFalse(SsrfGuard::isPublicIp('192.168.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('192.168.255.255'));
	}

	public function testIsPublicIpRejectsLoopback(): void
	{
		self::assertFalse(SsrfGuard::isPublicIp('127.0.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('127.255.255.255'));
		self::assertFalse(SsrfGuard::isPublicIp('::1'));
	}

	public function testIsPublicIpRejectsLinkLocal(): void
	{
		// Includes the AWS/GCP metadata service address 169.254.169.254
		self::assertFalse(SsrfGuard::isPublicIp('169.254.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('169.254.169.254'));
		self::assertFalse(SsrfGuard::isPublicIp('fe80::1'));
	}

	public function testIsPublicIpRejectsCgnat(): void
	{
		// RFC 6598 - 100.64.0.0/10
		self::assertFalse(SsrfGuard::isPublicIp('100.64.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('100.127.255.254'));
	}

	public function testIsPublicIpRejectsDocumentationRanges(): void
	{
		// 198.18.0.0/15 - benchmarking
		self::assertFalse(SsrfGuard::isPublicIp('198.18.0.1'));
		self::assertFalse(SsrfGuard::isPublicIp('198.19.255.254'));
	}

	public function testIsPublicIpRejectsZeroAddress(): void
	{
		self::assertFalse(SsrfGuard::isPublicIp('0.0.0.0'));
	}

	public function testIsPublicIpRejectsIPv6UniqueLocal(): void
	{
		self::assertFalse(SsrfGuard::isPublicIp('fc00::1'));
		self::assertFalse(SsrfGuard::isPublicIp('fd00::1'));
	}

	public function testIsPublicIpRejectsInvalidInput(): void
	{
		self::assertFalse(SsrfGuard::isPublicIp('not-an-ip'));
		self::assertFalse(SsrfGuard::isPublicIp(''));
		self::assertFalse(SsrfGuard::isPublicIp('999.999.999.999'));
	}

	public function testValidateRejectsLoopbackUrl(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);
		$this->expectExceptionMessage('private or reserved IP');

		$guard->validate('https://127.0.0.1/path');
	}

	public function testValidateRejectsPrivateIpUrl(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);
		$this->expectExceptionMessage('private or reserved IP');

		$guard->validate('https://192.168.1.1/path');
	}

	public function testValidateRejectsAwsMetadataAddress(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);
		$this->expectExceptionMessage('private or reserved IP');

		$guard->validate('http://169.254.169.254/latest/meta-data/');
	}

	public function testValidateRejectsNonHttpScheme(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);
		$this->expectExceptionMessage('Only http/https');

		$guard->validate('file:///etc/passwd');
	}

	public function testValidateRejectsUrlWithoutHost(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);

		$guard->validate('not-a-url');
	}

	public function testValidateRejectsUnresolvableHost(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);
		$this->expectExceptionMessage('Could not resolve host');

		$guard->validate('https://this-domain-definitely-does-not-exist-'.uniqid().'.invalid/path');
	}

	public function testValidateAcceptsIPv6Loopback(): void
	{
		$guard = new SsrfGuard();

		$this->expectException(NetworkException::class);

		$guard->validate('http://[::1]/path');
	}
}
