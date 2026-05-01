<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Storage\Pdo;

/**
 * Builds an INSERT-or-UPDATE statement targeting the dialect of the active PDO driver.
 *
 * MySQL/MariaDB use `INSERT ... ON DUPLICATE KEY UPDATE col = VALUES(col)`; PostgreSQL
 * and SQLite use `INSERT ... ON CONFLICT (key) DO UPDATE SET col = EXCLUDED.col`. Both
 * shapes are produced from the same column list so the caller binds parameters once.
 *
 * @internal
 */
final class UpsertSqlBuilder
{
	/**
	 * @param string $driver PDO driver name as reported by PDO::ATTR_DRIVER_NAME ('mysql', 'pgsql', 'sqlite')
	 * @param string $table Table name (interpolated as-is — caller is responsible for trusting it)
	 * @param list<string> $insertColumns Columns in the INSERT clause; named parameters are derived as `:column`
	 * @param string $conflictColumn Column name forming the unique key
	 * @param list<string> $updateColumns Columns to update on conflict (typically every $insertColumns entry except the key)
	 */
	public static function build(
		string $driver,
		string $table,
		array $insertColumns,
		string $conflictColumn,
		array $updateColumns,
	): string {
		$cols = implode(', ', $insertColumns);
		$placeholders = implode(', ', array_map(
			static fn(string $c): string => ':'.$c,
			$insertColumns,
		));

		if ($driver === 'mysql') {
			$updateSet = implode(",\n    ", array_map(
				static fn(string $c): string => $c.' = VALUES('.$c.')',
				$updateColumns,
			));

			return "INSERT INTO {$table} ({$cols}) VALUES ({$placeholders})\n"
				."ON DUPLICATE KEY UPDATE\n    {$updateSet}";
		}

		$updateSet = implode(",\n    ", array_map(
			static fn(string $c): string => $c.' = EXCLUDED.'.$c,
			$updateColumns,
		));

		return "INSERT INTO {$table} ({$cols}) VALUES ({$placeholders})\n"
			."ON CONFLICT ({$conflictColumn}) DO UPDATE SET\n    {$updateSet}";
	}
}
