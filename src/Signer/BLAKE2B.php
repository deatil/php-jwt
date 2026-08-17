<?php

declare(strict_types=1);

namespace Deatil\JWT\Signer;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Exception\InvalidKeyProvided;

use function strlen;
use function hash_equals;
use function sodium_crypto_generichash;

/**
 * BLAKE2B signers
 */
final class BLAKE2B extends BaseSigner
{
    private const MINIMUM_KEY_LENGTH_IN_BITS = 256;

    public function getAlgorithmId(): string
    {
        return 'BLAKE2B';
    }

    public function createSignature(string $payload, Key $key): string
    {
        $actualKeyLength = 8 * strlen($key->getContent());

        if ($actualKeyLength < self::MINIMUM_KEY_LENGTH_IN_BITS) {
            throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH_IN_BITS, $actualKeyLength);
        }

        return sodium_crypto_generichash($payload, $key->getContent());
    }

    public function verifySignature(string $expected, string $payload, Key $key): bool
    {
        return hash_equals($expected, $this->createSignature($payload, $key));
    }
}
