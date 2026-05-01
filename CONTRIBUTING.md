# Contributing to atproto-php

Thank you for considering a contribution. This guide covers the development setup, coding standards, and pull request process.

## Requirements

- PHP 8.2 or newer
- Extensions: `json`, `curl`, `openssl`, `sodium`, `pdo_sqlite` (for PDO storage tests)
- [Composer](https://getcomposer.org/)

## Getting started

```bash
git clone https://github.com/gimucco/atproto-php.git
cd atproto-php
composer install
```

## Running tests

The test suite uses PHPUnit 10:

```bash
composer test
```

To generate an HTML coverage report (requires Xdebug or PCOV):

```bash
composer test-coverage
```

The report will be written to the `coverage/` directory.

## Static analysis

PHPStan is configured at level 8 with strict rules:

```bash
composer phpstan
```

All pull requests must pass PHPStan without errors.

## Code style

This project follows PER Coding Style 2.0 via PHP-CS-Fixer.

Check for violations:

```bash
composer cs-check
```

Auto-fix violations:

```bash
composer cs-fix
```

Please run `composer cs-fix` before committing.

## Manual testing

The `examples/` directory contains a full working OAuth flow you can use to test changes against a real AT Protocol authorization server. See [`examples/README.md`](examples/README.md) for setup instructions.

## Pull request guidelines

1. **Fork and branch.** Create a feature branch from `main` (e.g., `feature/dpop-retry-limit`).
2. **Keep changes focused.** One logical change per PR.
3. **Add tests.** New features and bug fixes should include unit tests.
4. **Pass CI.** All of the following must pass:
   - `composer test`
   - `composer phpstan`
   - `composer cs-check`
5. **Write a clear description.** Explain *what* changed and *why*.

## Project structure

```
src/
  ClientConfig.php              # Configuration value object
  ClientMetadataBuilder.php     # Client metadata / JWKS generation
  OAuthClient.php               # Main OAuth flow orchestrator
  Session.php                   # Active session with authenticated requests
  StoredSession.php             # Serializable session data
  SessionStoreInterface.php     # Session persistence contract
  StateStoreInterface.php       # OAuth state persistence contract
  Storage/                      # Built-in storage implementations
    FileSessionStore.php
    FileStateStore.php
    PdoSessionStore.php
    PdoStateStore.php
    InMemorySessionStore.php
    InMemoryStateStore.php
    EncryptionHelper.php
  Internal/                     # Internal implementation details
    Dpop/
    Http/
    Jwt/
    Pkce/
    Resolver/
  Exception/                    # Exception hierarchy
tests/
examples/
```

Classes under `Internal/` are not part of the public API and may change without notice.

## Reporting issues

Open an issue on GitHub with:

- A clear title describing the problem
- Steps to reproduce (if applicable)
- Expected vs. actual behavior
- PHP version and relevant extension versions

## License

By contributing, you agree that your contributions will be licensed under the GPL-2.0-or-later license.
