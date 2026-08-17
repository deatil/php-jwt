<?php

declare(strict_types=1);

namespace Deatil\JWT\Signer\Ecdsa;

use Deatil\JWT\Signer\Ecdsa;

/**
 * Signer for ECDSA P256K SHA-256
 */
final class ES256K extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES256K';
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
