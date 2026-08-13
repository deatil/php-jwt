<?php

declare (strict_types = 1);

namespace Deatil\JWT\Signer\Hmac;

use Deatil\JWT\Signer\Hmac;

/**
 * Signer for HMAC SHA-512
 */
final class Sha512 extends Hmac
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'HS512';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): string
    {
        return 'sha512';
    }
}
