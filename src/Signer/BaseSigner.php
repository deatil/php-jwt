<?php

declare (strict_types = 1);

namespace Deatil\JWT\Signer;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Contracts\Signer;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Claim\RegisteredHeaders;

use function is_string;

/**
 * Base class for signers
 */
abstract class BaseSigner implements Signer
{
    /**
     * {@inheritdoc}
     */
    public function modifyHeader(array &$headers): void
    {
        $headers[RegisteredHeaders::ALGORITHM] = $this->getAlgorithmId();
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $payload, Key $key): string
    {
        return $this->createSignature($payload, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature($expected, $payload, $key);
    }

    /**
     * Creates a hash with the given data
     *
     * @internal
     *
     * @param string $payload
     * @param Key    $key
     *
     * @return string
     */
    abstract public function createSignature(string $payload, Key $key): string;

    /**
     * Performs the signature verification
     *
     * @internal
     *
     * @param string $expected
     * @param string $payload
     * @param Key    $key
     *
     * @return boolean
     */
    abstract public function verifySignature(string $expected, string $payload, Key $key): bool;
}
