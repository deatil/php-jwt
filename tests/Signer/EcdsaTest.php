<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Signer;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Signer\Ecdsa\ES256;
use Deatil\JWT\Signer\Ecdsa\ES384;
use Deatil\JWT\Signer\Ecdsa\ES512;
use Deatil\JWT\Signer\Ecdsa\ES256K;

class EcdsaTest extends TestCase
{
    public function testES256(): void
    {
        $msg  = "test-data";
        $sign = "eeb2f460f51158dfbefe212cf66e76e7bf8df5f8ef47929443ad47a6b094ef51cc9faa00b32e54cb657e13f9e1c9c5814c3ac194fb57b23d5d7575889b090bf9";

        $prikey = "-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg/DkEwUlK8nWyB30J
RyxjU42bu//wSrGj2szLE/ybKMqgCgYIKoZIzj0DAQehRANCAAROkh8yLuhNymC1
t5DSS6XNiUAotBK3Wl84ZQe0e9x7wwSyy547EIdYkqqX+wn4mslJ+o67kBaUOoaq
nvtkDskL
-----END PRIVATE KEY-----";
        $pubkey = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpIfMi7oTcpgtbeQ0kulzYlAKLQS
t1pfOGUHtHvce8MEssueOxCHWJKql/sJ+JrJSfqOu5AWlDqGqp77ZA7JCw==
-----END PUBLIC KEY-----";

        $h = new ES256();

        $algo = $h->getAlgorithmId();
        self::assertSame("ES256", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }

    public function testES384(): void
    {
        $msg  = "test-data";
        $sign = "b8b23858c95d3bec18e791ae74bd3f4062aed0ef164f95e1509099f04a776d1ef4906d5b4b2fa3dff20cc5a3521cd285662972c3b58ffa3fd9b7639bfd86a11d375128bd69ae3e97210e3ceec7307308e816fddb098a68be7f47ceb5fde55d77";

        $prikey = "-----BEGIN PRIVATE KEY-----
MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCKkU3/bJJS2nV+u4FS
gCLgcaNaDnyB7sEEhXvCLf4DJiLWplxb/lNdHKtEVbx828OgBwYFK4EEACKhZANi
AATOXjuGfhl/4JylsxuaEw4fxIOXle0hJD1AJODcC8e3KJSMG5MGhKLQPvo2IZAd
9IK7byRArzegzwtMjAnGzE9oIXnCm7JczuyX4sRPoL8d+RNtc7ZVjEL/srgTWohW
A3s=
-----END PRIVATE KEY-----";
        $pubkey = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzl47hn4Zf+CcpbMbmhMOH8SDl5XtISQ9
QCTg3AvHtyiUjBuTBoSi0D76NiGQHfSCu28kQK83oM8LTIwJxsxPaCF5wpuyXM7s
l+LET6C/HfkTbXO2VYxC/7K4E1qIVgN7
-----END PUBLIC KEY-----";

        $h = new ES384();

        $algo = $h->getAlgorithmId();
        self::assertSame("ES384", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }

    public function testES512(): void
    {
        $msg  = "test-data";
        $sign = "00b6b7d7dc3102fdba7a399c8bc7e3131a0892cac2322349a03aa9166303f1036fae59510e1d8dc52f4e384c5f9644abe680effa8b0942decae0021dccc5e6a54a2101b9037433f6fe9fae623bea369f7da9a52a1c69089ed3fbb9900da3d4db6894bac86af232e8589219cc32f19d84232ee510ce9665e71f852b317c59c4b6ca773bc8";

        $prikey = "-----BEGIN PRIVATE KEY-----
MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIAyYKP3zmWUSvKgv9B
YFSQ8SNvCUWQ+ac4o8xxVxQ0xJJYi5r86HoOcPafRhA08FpL5QsbH09t7SIb4/u3
SRoaHamgBwYFK4EEACOhgYkDgYYABAHlKXMgRKArgvYmeANJpFSbOlD51GpU/jnQ
zhWoomjv4MT/Urz4tTzkMY1gWNIpMFNYKzczdT6QWcaCvYx80fN20ACwZYQpDhb4
lAo3rKovPU5wBzwGfMDMX3WYaPCglREuk1mV13TLW5xsv0SbKOoHQuaGiQ8Vb2W0
QQwS8iecuQQq8g==
-----END PRIVATE KEY-----";
        $pubkey = "-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB5SlzIESgK4L2JngDSaRUmzpQ+dRq
VP450M4VqKJo7+DE/1K8+LU85DGNYFjSKTBTWCs3M3U+kFnGgr2MfNHzdtAAsGWE
KQ4W+JQKN6yqLz1OcAc8BnzAzF91mGjwoJURLpNZldd0y1ucbL9EmyjqB0LmhokP
FW9ltEEMEvInnLkEKvI=
-----END PUBLIC KEY-----";

        $h = new ES512();

        $algo = $h->getAlgorithmId();
        self::assertSame("ES512", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }

    public function testES256K(): void
    {
        $msg  = "test-data";
        $sign = "2ec44403fe2c3630685bf425024cff3cfafe346be8b624cd461763cb4dfdae50e82c14639e496844b83554665be8a3bdcdbcbc7057bb068a07821fe6a81ec91a";

        $prikey = "-----BEGIN PRIVATE KEY-----
MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgxOKd7ezy1P7xuzAMzj/P
yj7AhgZv09A+vDzHo27pAN2gBwYFK4EEAAqhRANCAATLzC6/r59eh0s8t+HGbXfb
LVHybh2SeDu0d7s36xQtXYS2HoDERdB934Tie5x5HbVQ0K9AqrGJjALNXAgpwd78
-----END PRIVATE KEY-----";
        $pubkey = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy8wuv6+fXodLPLfhxm132y1R8m4dkng7
tHe7N+sULV2Eth6AxEXQfd+E4nuceR21UNCvQKqxiYwCzVwIKcHe/A==
-----END PUBLIC KEY-----";

        $h = new ES256K();

        $algo = $h->getAlgorithmId();
        self::assertSame("ES256K", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }
}
