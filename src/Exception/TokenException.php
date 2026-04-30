<?php

declare(strict_types=1);

namespace Gimucco\Atproto\Exception;

final class TokenException extends AuthorizationException
{
	public function __construct(
		public readonly string $error,
		public readonly string $errorDescription = '',
		public readonly string $errorUri = '',
		?\Throwable $previous = null,
	) {
		$message = $this->error;
		if ($this->errorDescription !== '') {
			$message .= ': '.$this->errorDescription;
		}

		parent::__construct($message, 0, $previous);
	}
}
