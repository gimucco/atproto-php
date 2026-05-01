<?php

declare(strict_types=1);

return [
	'client_id' => 'https://your-domain.com/atproto/client-metadata.json',
	// Single redirect URI:
	'redirect_uri' => 'https://your-domain.com/atproto/callback',
	// Or multiple — useful when one client_id serves several flows
	// (e.g., login + account linking). All URIs are declared in
	// client-metadata.json; pick one per ClientConfig at runtime.
	// 'redirect_uri' => [
	//     'https://your-domain.com/atproto/callback/login',
	//     'https://your-domain.com/atproto/callback/link',
	// ],
	'scope' => 'atproto transition:generic',
	'client_name' => 'My AT Protocol App',
	'client_uri' => 'https://your-domain.com',
	'jwks_uri' => 'https://your-domain.com/atproto/jwks.json',
	'private_key_path' => __DIR__.'/private.pem',
	'encryption_passphrase' => 'change-me-to-a-strong-random-passphrase',
	'storage_dir' => __DIR__.'/storage',
];
