<?php

declare(strict_types=1);

namespace Deatil\JWT\Signer;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Contracts\SignatureConverter;
use Deatil\JWT\Converter\MultibyteStringConverter;

use const OPENSSL_KEYTYPE_EC;

/**
 * Base class for ECDSA signers
 */
abstract class Ecdsa extends OpenSSL
{
    /**
     * @var SignatureConverter
     */
    private $converter;

    public function __construct(
        ?SignatureConverter $converter = null
    ) {
        $this->converter = $converter ?: new MultibyteStringConverter();
    }

    /**
     * {@inheritdoc}
     */
    public function createSignature(string $payload, Key $key): string
    {
        return $this->converter->fromAsn1(
            parent::createSignature($payload, $key),
            $this->getKeyLength()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verifySignature(string $expected, string $payload, Key $key): bool
    {
        return parent::verifySignature(
            $this->converter->toAsn1($expected, $this->getKeyLength()),
            $payload,
            $key
        );
    }

    /**
     * Returns the length of each point in the signature, so that we can calculate and verify R and S points properly
     *
     * @internal
     */
    abstract public function getKeyLength(): int;

    /**
     * {@inheritdoc}
     */
    final public function getKeyType(): int
    {
        return OPENSSL_KEYTYPE_EC;
    }
}
