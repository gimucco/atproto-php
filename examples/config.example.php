<?php

declare(strict_types=1);

return [
	'client_id' => 'https://your-domain.com/atproto/client-metadata.json',
	'redirect_uri' => 'https://your-domain.com/atproto/callback',
	'scope' => 'atproto transition:generic',
	'client_name' => 'My AT Protocol App',
	'client_uri' => 'https://your-domain.com',
	'jwks_uri' => 'https://your-domain.com/atproto/jwks.json',
	'private_key_path' => __DIR__.'/private.pem',
	'encryption_passphrase' => 'change-me-to-a-strong-random-passphrase',
	'storage_dir' => __DIR__.'/storage',
];
