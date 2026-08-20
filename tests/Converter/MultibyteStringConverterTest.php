<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Converter;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Converter\MultibyteStringConverter;

class MultibyteStringConverterTest extends TestCase
{
    public function testToAsn1(): void
    {
        $msc = new MultibyteStringConverter();

        $data = "583a2510f448844f6de5acc333f89ea67f5ece4d1d22e13138a1581407554b5402de23b258cfffe1910088b802906b9a3e8d1fb55402b02608b632a05591e019";
        $encodedStr = "30440220583a2510f448844f6de5acc333f89ea67f5ece4d1d22e13138a1581407554b54022002de23b258cfffe1910088b802906b9a3e8d1fb55402b02608b632a05591e019";

        $encoded = $msc->toAsn1(hex2bin($data), 64);
        self::assertSame($encodedStr, bin2hex($encoded));
    }

    public function testFromAsn1(): void
    {
        $msc = new MultibyteStringConverter();

        $data = "30440220583a2510f448844f6de5acc333f89ea67f5ece4d1d22e13138a1581407554b54022002de23b258cfffe1910088b802906b9a3e8d1fb55402b02608b632a05591e019";
        $encodedStr = "583a2510f448844f6de5acc333f89ea67f5ece4d1d22e13138a1581407554b5402de23b258cfffe1910088b802906b9a3e8d1fb55402b02608b632a05591e019";

        $encoded = $msc->fromAsn1(hex2bin($data), 64);
        self::assertSame($encodedStr, bin2hex($encoded));
    }
}
