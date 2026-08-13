<?php

declare (strict_types = 1);

namespace Deatil\JWT\Signer\Hmac;

use Deatil\JWT\Signer\Hmac;

/**
 * Signer for HMAC SHA-384
 */
final class Sha384 extends Hmac
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'HS384';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): string
    {
        return 'sha384';
    }
}
