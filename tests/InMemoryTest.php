<?php
declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;

use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Key\LocalFileReference;

class InMemoryTest extends TestCase
{
    public function testEmpty(): void
    {
        $key = InMemory::empty();

        self::assertSame("", $key->getContent());
        self::assertSame("", $key->getPassphrase());
    }
    
    public function testPlainText(): void
    {
        $key = InMemory::plainText("text", "pass");

        self::assertSame("text", $key->getContent());
        self::assertSame("pass", $key->getPassphrase());
    }
    
    public function testBase64Encoded(): void
    {
        $key = InMemory::base64Encoded("YmFzZTY0IHRlc3Q=", "pass");

        self::assertSame("base64 test", $key->getContent());
        self::assertSame("pass", $key->getPassphrase());
    }
    
    public function testHexEncoded(): void
    {
        $key = InMemory::hexEncoded("6865782074657374", "pass");

        self::assertSame("hex test", $key->getContent());
        self::assertSame("pass", $key->getPassphrase());
    }
    
    public function testFile(): void
    {
        $key = InMemory::file(__DIR__ . '/_keys/ecdsa/private.key', "pass");
        $prikey = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBGpMoZJ64MMSzuo5JbmXpf9V4qSWdLIl/8RmJLcfn/qoAoGCCqGSM49
AwEHoUQDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpnd0wxa2iFruiI2tsEdGFTLTsy
U+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==
-----END EC PRIVATE KEY-----";

        self::assertSame($prikey, $key->getContent());
        self::assertSame("pass", $key->getPassphrase());
    }

    public function testFile2(): void
    {
        $key = LocalFileReference::file(__DIR__ . '/_keys/ecdsa/private.key', "pass");
        $prikey = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBGpMoZJ64MMSzuo5JbmXpf9V4qSWdLIl/8RmJLcfn/qoAoGCCqGSM49
AwEHoUQDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpnd0wxa2iFruiI2tsEdGFTLTsy
U+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==
-----END EC PRIVATE KEY-----";

        self::assertSame($prikey, $key->getContent());
        self::assertSame("pass", $key->getPassphrase());
    }

}
