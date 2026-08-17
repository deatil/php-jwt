<?php

declare(strict_types=1);

namespace Deatil\JWT\Signer;

use SodiumException;
use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Exception\InvalidKeyProvided;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * EdDSA signers
 */
final class EdDSA extends BaseSigner
{
    public function getAlgorithmId(): string
    {
        return 'EdDSA';
    }

    public function createSignature(string $payload, Key $key): string
    {
        try {
            return sodium_crypto_sign_detached($payload, $key->getContent());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided("EdDSA Create error: " . $sodiumException->getMessage(), 0, $sodiumException);
        }
    }

    public function verifySignature(string $expected, string $payload, Key $key): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($expected, $payload, $key->getContent());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided("EdDSA Verify error: " . $sodiumException->getMessage(), 0, $sodiumException);
        }
    }
}
