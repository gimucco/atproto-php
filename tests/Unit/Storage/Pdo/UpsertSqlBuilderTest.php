<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Tests\Unit\Storage\Pdo;

use Gimucco\Atproto\Storage\Pdo\UpsertSqlBuilder;
use PHPUnit\Framework\TestCase;

final class UpsertSqlBuilderTest extends TestCase
{
	public function testMysqlEmitsOnDuplicateKeyUpdate(): void
	{
		$sql = UpsertSqlBuilder::build(
			driver: 'mysql',
			table: 'atproto_oauth_states',
			insertColumns: ['state_key', 'payload', 'expires_at'],
			conflictColumn: 'state_key',
			updateColumns: ['payload', 'expires_at'],
		);

		self::assertStringContainsString(
			'INSERT INTO atproto_oauth_states (state_key, payload, expires_at)',
			$sql,
		);
		self::assertStringContainsString(
			'VALUES (:state_key, :payload, :expires_at)',
			$sql,
		);
		self::assertStringContainsString('ON DUPLICATE KEY UPDATE', $sql);
		self::assertStringContainsString('payload = VALUES(payload)', $sql);
		self::assertStringContainsString('expires_at = VALUES(expires_at)', $sql);

		// MySQL must not pick up the PostgreSQL/SQLite dialect
		self::assertStringNotContainsString('ON CONFLICT', $sql);
		self::assertStringNotContainsString('EXCLUDED', $sql);
	}

	public function testPgsqlEmitsOnConflictWithExcluded(): void
	{
		$sql = UpsertSqlBuilder::build(
			driver: 'pgsql',
			table: 'atproto_oauth_states',
			insertColumns: ['state_key', 'payload', 'expires_at'],
			conflictColumn: 'state_key',
			updateColumns: ['payload', 'expires_at'],
		);

		self::assertStringContainsString('ON CONFLICT (state_key) DO UPDATE SET', $sql);
		self::assertStringContainsString('payload = EXCLUDED.payload', $sql);
		self::assertStringContainsString('expires_at = EXCLUDED.expires_at', $sql);

		// PostgreSQL must not pick up the MySQL dialect
		self::assertStringNotContainsString('ON DUPLICATE KEY UPDATE', $sql);
		self::assertStringNotContainsString('VALUES(payload)', $sql);
	}

	public function testSqliteEmitsOnConflictWithExcluded(): void
	{
		$sql = UpsertSqlBuilder::build(
			driver: 'sqlite',
			table: 'atproto_oauth_states',
			insertColumns: ['state_key', 'payload', 'expires_at'],
			conflictColumn: 'state_key',
			updateColumns: ['payload', 'expires_at'],
		);

		self::assertStringContainsString('ON CONFLICT (state_key) DO UPDATE SET', $sql);
		self::assertStringContainsString('payload = EXCLUDED.payload', $sql);
		self::assertStringNotContainsString('ON DUPLICATE KEY UPDATE', $sql);
	}

	public function testKeyColumnIsNotInUpdateSet(): void
	{
		// The conflict column itself should never appear in the update list — that's the caller's job.
		$mysql = UpsertSqlBuilder::build(
			driver: 'mysql',
			table: 't',
			insertColumns: ['did', 'handle'],
			conflictColumn: 'did',
			updateColumns: ['handle'],
		);

		self::assertStringContainsString('handle = VALUES(handle)', $mysql);
		self::assertStringNotContainsString('did = VALUES(did)', $mysql);
	}

	public function testSessionStoreShapeMysql(): void
	{
		$sql = UpsertSqlBuilder::build(
			driver: 'mysql',
			table: 'atproto_sessions',
			insertColumns: [
				'did', 'handle', 'pds_url', 'auth_server_issuer', 'token_endpoint',
				'access_token', 'refresh_token', 'dpop_private_key_pem', 'expires_at', 'scope',
			],
			conflictColumn: 'did',
			updateColumns: [
				'handle', 'pds_url', 'auth_server_issuer', 'token_endpoint',
				'access_token', 'refresh_token', 'dpop_private_key_pem', 'expires_at', 'scope',
			],
		);

		self::assertStringContainsString('ON DUPLICATE KEY UPDATE', $sql);
		self::assertStringContainsString('access_token = VALUES(access_token)', $sql);
		self::assertStringContainsString('refresh_token = VALUES(refresh_token)', $sql);
		self::assertStringContainsString('dpop_private_key_pem = VALUES(dpop_private_key_pem)', $sql);
		self::assertStringNotContainsString('did = VALUES(did)', $sql);
	}

	public function testSessionStoreShapePgsql(): void
	{
		$sql = UpsertSqlBuilder::build(
			driver: 'pgsql',
			table: 'atproto_sessions',
			insertColumns: [
				'did', 'handle', 'pds_url', 'auth_server_issuer', 'token_endpoint',
				'access_token', 'refresh_token', 'dpop_private_key_pem', 'expires_at', 'scope',
			],
			conflictColumn: 'did',
			updateColumns: [
				'handle', 'pds_url', 'auth_server_issuer', 'token_endpoint',
				'access_token', 'refresh_token', 'dpop_private_key_pem', 'expires_at', 'scope',
			],
		);

		self::assertStringContainsString('ON CONFLICT (did) DO UPDATE SET', $sql);
		self::assertStringContainsString('access_token = EXCLUDED.access_token', $sql);
		self::assertStringNotContainsString('did = EXCLUDED.did', $sql);
	}
}
