<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Signer;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Signer\EdDSA;
use Deatil\JWT\Signer\ED25519;
use Deatil\JWT\Exception\InvalidKeyProvided;

class EddsaTest extends TestCase
{
    public function testSignTooShort(): void
    {
        $msg    = "test-data";
        $pubkey = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";

        $h = new ED25519();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('($signature) must be SODIUM_CRYPTO_SIGN_BYTES bytes long');

        $sign = "hello";
        $veri = $h->verify($sign, $msg, InMemory::hexEncoded($pubkey));
    }

    public function testEdDSA(): void
    {
        $msg  = "test-data";
        $sign = "cf68669677c698b996b8f20e52f3a6b882fdb45c5c61806fd12e72c2a5a9db2c7522d248c1ba7c4aec68084fc5e87f1be7e8d802fe48268498522dcab7defe0f";

        $prikey = "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
        $pubkey = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";

        $h = new EdDSA();

        $algo = $h->getAlgorithmId();
        self::assertSame("EdDSA", $algo);

        $signed = $h->sign($msg, InMemory::hexEncoded($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::hexEncoded($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::hexEncoded($pubkey));
        self::assertTrue($veri2);

        $signed3 = "cf68669677c698b996b8f20e52f3a6b882fdb48c5c61806fd12e72c2a5a9db2c7522d248c1ba7c4aec68084fc5e87f1be7e8d802fe48268498522dcab7defe0f";
        $veri3 = $h->verify(hex2bin($signed3), $msg, InMemory::hexEncoded($pubkey));
        self::assertFalse($veri3);
    }

    public function testED25519(): void
    {
        $msg  = "test-data";
        $sign = "cf68669677c698b996b8f20e52f3a6b882fdb45c5c61806fd12e72c2a5a9db2c7522d248c1ba7c4aec68084fc5e87f1be7e8d802fe48268498522dcab7defe0f";

        $prikey = "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
        $pubkey = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";

        $h = new ED25519();

        $algo = $h->getAlgorithmId();
        self::assertSame("ED25519", $algo);

        $signed = $h->sign($msg, InMemory::hexEncoded($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::hexEncoded($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::hexEncoded($pubkey));
        self::assertTrue($veri2);

        $signed3 = "cf68669677c698b996b8f20e52f3a6b882fdb48c5c61806fd12e72c2a5a9db2c7522d248c1ba7c4aec68084fc5e87f1be7e8d802fe48268498522dcab7defe0f";
        $veri3 = $h->verify(hex2bin($signed3), $msg, InMemory::hexEncoded($pubkey));
        self::assertFalse($veri3);
    }
}
