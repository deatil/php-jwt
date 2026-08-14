<?php

declare (strict_types = 1);

namespace Deatil\JWT\Signer;

use SodiumException;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Exception\InvalidKeyProvided;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/**
 * Ed25519 signers
 */
final class Ed25519 extends BaseSigner
{
    public function getAlgorithmId(): string
    {
        return 'ED25519';
    }
    
    public function createHash(string $payload, Key $key): string
    {
        try {
            return sodium_crypto_sign_detached($payload, $key->getContent());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided("EdDSA Create error: " . $sodiumException->getMessage(), 0, $sodiumException);
        }
    }

    public function doVerify(string $expected, string $payload, Key $key): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($expected, $payload, $key->getContent());
        } catch (SodiumException $sodiumException) {
            throw new InvalidKeyProvided("EdDSA Verify error: " . $sodiumException->getMessage(), 0, $sodiumException);
        }
    }
}