<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
	->in([
		__DIR__ . '/src',
		__DIR__ . '/tests',
		__DIR__ . '/examples',
	])
	->name('*.php');

return (new PhpCsFixer\Config())
	->setRiskyAllowed(true)
	->setIndent("\t")
	->setRules([
		'@PER-CS2.0' => true,
		'@PER-CS2.0:risky' => true,
		'declare_strict_types' => true,
		'strict_param' => true,
		'array_syntax' => ['syntax' => 'short'],
		'no_unused_imports' => true,
		'ordered_imports' => ['sort_algorithm' => 'alpha'],
		'single_quote' => true,
		'trailing_comma_in_multiline' => ['elements' => ['arguments', 'arrays', 'parameters']],
		'native_function_invocation' => ['include' => ['@compiler_optimized'], 'scope' => 'namespaced', 'strict' => true],
		'concat_space' => ['spacing' => 'none'],
	])
	->setFinder($finder);
