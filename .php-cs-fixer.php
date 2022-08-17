<?php

declare(strict_types=1);

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__)
    ->name('*.php')
	->notName('*.asset.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

$rules = [
    '@PSR12' => true,
    '@PhpCsFixer' => true,
    '@Symfony' => true,
    '@Symfony:risky' => true,
    '@PHP80Migration' => true,
    '@PHP80Migration:risky' => true,
    'array_syntax' => ['syntax' => 'short'],
    'not_operator_with_successor_space' => false,
    'concat_space' => ['spacing' => 'one'],
    'declare_strict_types' => true,
    'void_return' => true,
    'native_function_invocation' => ['include' => ['@all']],
    'multiline_whitespace_before_semicolons' => ['strategy' => 'no_multi_line'],
    'phpdoc_to_comment' => false,
    'single_line_throw' => false,
    'echo_tag_syntax' => ['format' => 'short'],
    'simplified_if_return' => true,
    'simplified_null_return' => true,
];

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setLineEnding("\n")
    ->setRules($rules)
    ->setFinder($finder);
