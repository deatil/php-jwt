<?php

declare(strict_types=1);

namespace Deatil\JWT\Signer\Ecdsa;

use Deatil\JWT\Signer\Ecdsa;

/**
 * Signer for ECDSA SHA-256
 */
final class ES256 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): mixed
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return 64;
    }
}
