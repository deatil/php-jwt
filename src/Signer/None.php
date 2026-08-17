<?php

declare (strict_types = 1);

namespace Deatil\JWT\Signer;

use Deatil\JWT\Contracts\Key;

/**
 * None signers
 */
final class None extends BaseSigner
{
    public function getAlgorithmId(): string
    {
        return 'none';
    }

    public function createSignature(string $payload, Key $key): string
    {
        return "";
    }

    public function verifySignature(string $expected, string $payload, Key $key): bool
    {
        return $expected === '';
    }
}