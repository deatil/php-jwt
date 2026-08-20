<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Signer;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Signer\None;
use Deatil\JWT\Key\InMemory;

class NoneTest extends TestCase
{
    public function testNone(): void
    {
        $msg  = "test-data";
        $key  = "";
        $sign = "";

        $h = new None();

        $algo = $h->getAlgorithmId();
        self::assertSame("none", $algo);

        $signed = $h->sign($msg, InMemory::plainText($key));
        self::assertSame($sign, $signed);

        $veri = $h->verify($signed, $msg, InMemory::plainText($key));
        self::assertTrue($veri);
    }
}
