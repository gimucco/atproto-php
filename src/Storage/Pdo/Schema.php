<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage\Pdo;

final class Schema
{
	/**
	 * @param string $driver PDO driver name ('mysql', 'pgsql', 'sqlite')
	 * @param string $sessionsTable Table name for sessions
	 * @param string $statesTable Table name for OAuth states
	 *
	 * @return array{sessions: string, states: string}
	 */
	public static function createTablesSql(
		string $driver = 'mysql',
		string $sessionsTable = 'atproto_sessions',
		string $statesTable = 'atproto_oauth_states',
	): array {
		return match ($driver) {
			'mysql' => self::mysql($sessionsTable, $statesTable),
			'pgsql' => self::pgsql($sessionsTable, $statesTable),
			'sqlite' => self::sqlite($sessionsTable, $statesTable),
			default => throw new \InvalidArgumentException('Unsupported PDO driver: '.$driver),
		};
	}

	/**
	 * @return array{sessions: string, states: string}
	 */
	private static function mysql(string $sessionsTable, string $statesTable): array
	{
		return [
			'sessions' => <<<SQL
                CREATE TABLE IF NOT EXISTS `{$sessionsTable}` (
                    `did` VARCHAR(255) NOT NULL PRIMARY KEY,
                    `handle` VARCHAR(255) NOT NULL,
                    `pds_url` VARCHAR(1024) NOT NULL,
                    `auth_server_issuer` VARCHAR(1024) NOT NULL,
                    `token_endpoint` VARCHAR(1024) NOT NULL,
                    `access_token` TEXT NOT NULL,
                    `refresh_token` TEXT NOT NULL,
                    `dpop_private_key_pem` TEXT NOT NULL,
                    `expires_at` INT UNSIGNED NOT NULL,
                    `scope` VARCHAR(512) NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
			'states' => <<<SQL
                CREATE TABLE IF NOT EXISTS `{$statesTable}` (
                    `state_key` VARCHAR(255) NOT NULL PRIMARY KEY,
                    `payload` TEXT NOT NULL,
                    `expires_at` INT UNSIGNED NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                SQL,
		];
	}

	/**
	 * @return array{sessions: string, states: string}
	 */
	private static function pgsql(string $sessionsTable, string $statesTable): array
	{
		return [
			'sessions' => <<<SQL
                CREATE TABLE IF NOT EXISTS "{$sessionsTable}" (
                    "did" VARCHAR(255) NOT NULL PRIMARY KEY,
                    "handle" VARCHAR(255) NOT NULL,
                    "pds_url" VARCHAR(1024) NOT NULL,
                    "auth_server_issuer" VARCHAR(1024) NOT NULL,
                    "token_endpoint" VARCHAR(1024) NOT NULL,
                    "access_token" TEXT NOT NULL,
                    "refresh_token" TEXT NOT NULL,
                    "dpop_private_key_pem" TEXT NOT NULL,
                    "expires_at" INTEGER NOT NULL,
                    "scope" VARCHAR(512) NOT NULL,
                    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    "updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                SQL,
			'states' => <<<SQL
                CREATE TABLE IF NOT EXISTS "{$statesTable}" (
                    "state_key" VARCHAR(255) NOT NULL PRIMARY KEY,
                    "payload" TEXT NOT NULL,
                    "expires_at" INTEGER NOT NULL,
                    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                SQL,
		];
	}

	/**
	 * @return array{sessions: string, states: string}
	 */
	private static function sqlite(string $sessionsTable, string $statesTable): array
	{
		return [
			'sessions' => <<<SQL
                CREATE TABLE IF NOT EXISTS "{$sessionsTable}" (
                    "did" TEXT NOT NULL PRIMARY KEY,
                    "handle" TEXT NOT NULL,
                    "pds_url" TEXT NOT NULL,
                    "auth_server_issuer" TEXT NOT NULL,
                    "token_endpoint" TEXT NOT NULL,
                    "access_token" TEXT NOT NULL,
                    "refresh_token" TEXT NOT NULL,
                    "dpop_private_key_pem" TEXT NOT NULL,
                    "expires_at" INTEGER NOT NULL,
                    "scope" TEXT NOT NULL,
                    "created_at" TEXT DEFAULT (datetime('now')),
                    "updated_at" TEXT DEFAULT (datetime('now'))
                )
                SQL,
			'states' => <<<SQL
                CREATE TABLE IF NOT EXISTS "{$statesTable}" (
                    "state_key" TEXT NOT NULL PRIMARY KEY,
                    "payload" TEXT NOT NULL,
                    "expires_at" INTEGER NOT NULL,
                    "created_at" TEXT DEFAULT (datetime('now'))
                )
                SQL,
		];
	}
}
