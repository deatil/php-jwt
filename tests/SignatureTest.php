<?php
declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;

use Deatil\JWT\Signature;

class SignatureTest extends TestCase
{
    public function testSignature(): void
    {
        $hash    = "12345678";
        $encoded = "abcdefddgtfs32456";
        $sig     = new Signature($hash, $encoded);

        self::assertSame($hash, $sig->hash());
        self::assertSame($encoded, $sig->toString());
    }

}
