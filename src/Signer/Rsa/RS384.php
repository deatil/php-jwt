<?php

declare(strict_types=1);

namespace Deatil\JWT\Signer\Rsa;

use Deatil\JWT\Signer\Rsa;

use const OPENSSL_ALGO_SHA384;

/**
 * Signer for RSA SHA-384
 */
final class RS384 extends Rsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'RS384';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): mixed
    {
        return OPENSSL_ALGO_SHA384;
    }
}
