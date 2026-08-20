<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Encoding;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Encoding\JoseEncoder;

class JoseEncoderTest extends TestCase
{
    public function testBase64UrlEncode(): void
    {
        $je = new JoseEncoder();

        $encoded = $je->base64UrlEncode("base64 test");
        self::assertSame("YmFzZTY0IHRlc3Q", $encoded);

        $decoded = $je->base64UrlDecode($encoded);
        self::assertSame("base64 test", $decoded);
    }

    public function testJsonEncode(): void
    {
        $data = [
            "test"      => "asdfg",
            "int"       => 1278545,
            "test_bool" => true,
        ];
        $encode = '{"test":"asdfg","int":1278545,"test_bool":true}';

        $je = new JoseEncoder();

        $encoded = $je->jsonEncode($data);
        self::assertSame($encode, $encoded);

        $decoded = $je->jsonDecode($encoded);
        self::assertSame($data, $decoded);
    }
}
