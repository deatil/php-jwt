<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Signer;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Signer\Blake2b;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

class Blake2bTest extends TestCase
{
    public function testKeyTooShort(): void
    {
        $msg  = "test-data";
        $key  = "1234567890123";
        $sign = "d40bb120a0915ab65e0051fca93854775bd1380a1fb012ebd5c5df361159937e";

        $h = new Blake2b();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits');

        $veri = $h->verify($sign, $msg, InMemory::plainText($key));
    }

    public function testBlake2b(): void
    {
        $msg  = "test-data";
        $key  = "12345678901234567890as1234567890";
        $sign = "d40bb120a0915ab65e0051fca93854775bd1380a1fb012ebd5c5df361159937e";

        $h = new Blake2b();

        $algo = $h->getAlgorithmId();
        self::assertSame("BLAKE2B", $algo);

        $signed = $h->sign($msg, InMemory::plainText($key));
        self::assertSame($sign, bin2hex($signed));

        $veri = $h->verify($signed, $msg, InMemory::plainText($key));
        self::assertTrue($veri);

        $signed2 = "hello";
        $veri2 = $h->verify($signed2, $msg, InMemory::plainText($key));
        self::assertFalse($veri2);
    }
}
