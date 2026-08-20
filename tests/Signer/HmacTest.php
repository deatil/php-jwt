<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Signer;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Signer\Hmac\HS256;
use Deatil\JWT\Signer\Hmac\HS384;
use Deatil\JWT\Signer\Hmac\HS512;

class HmacTest extends TestCase
{
    public function testHS256(): void
    {
        $msg  = "test-data";
        $key  = "test-key";
        $sign = "21a286fd6fd9f52676007c66d0f883db46d06158c266d33fb537c23bc618e567";

        $h = new HS256();

        $algo = $h->getAlgorithmId();
        self::assertSame("HS256", $algo);

        $signed = $h->sign($msg, InMemory::plainText($key));
        self::assertSame($sign, bin2hex($signed));

        $veri = $h->verify($signed, $msg, InMemory::plainText($key));
        self::assertTrue($veri);

        $signed2 = "hello";
        $veri2 = $h->verify($signed2, $msg, InMemory::plainText($key));
        self::assertFalse($veri2);
    }

    public function testHS384(): void
    {
        $msg  = "test-data";
        $key  = "test-key";
        $sign = "7ef9106e87232142b352343c291d323498d8a8426029181ddf61a65d0f1bc2c497c86a1091f66d97c2179a18d6e67bdf";

        $h = new HS384();

        $algo = $h->getAlgorithmId();
        self::assertSame("HS384", $algo);

        $signed = $h->sign($msg, InMemory::plainText($key));
        self::assertSame($sign, bin2hex($signed));

        $veri = $h->verify($signed, $msg, InMemory::plainText($key));
        self::assertTrue($veri);

        $signed2 = "hello";
        $veri2 = $h->verify($signed2, $msg, InMemory::plainText($key));
        self::assertFalse($veri2);
    }

    public function testHS512(): void
    {
        $msg  = "test-data";
        $key  = "test-key";
        $sign = "080e166f475f1c5d61f26b94d45a0cd822729a525e3a3865b87cdf58a36f039ea1948735aab3ad5027d553ad06487fb57d3a9034d2861300297d6cebf838f5bf";

        $h = new HS512();

        $algo = $h->getAlgorithmId();
        self::assertSame("HS512", $algo);

        $signed = $h->sign($msg, InMemory::plainText($key));
        self::assertSame($sign, bin2hex($signed));

        $veri = $h->verify($signed, $msg, InMemory::plainText($key));
        self::assertTrue($veri);

        $signed2 = "hello";
        $veri2 = $h->verify($signed2, $msg, InMemory::plainText($key));
        self::assertFalse($veri2);
    }
}
