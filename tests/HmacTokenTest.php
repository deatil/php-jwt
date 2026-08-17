<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Facade;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Hmac\HS256;
use Deatil\JWT\Signer\Hmac\HS384;
use Deatil\JWT\Signer\Hmac\HS512;
use Deatil\JWT\Key\InMemory;

class HmacTokenTest extends TestCase
{
    public function testBuilder(): void
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new HS256();
        $key    = InMemory::plainText('testing');

        $token = (new Builder())->identifiedBy('1')
                     ->permittedFor('https://client.abc.com')
                     ->issuedBy('https://api.abc.com')
                     ->issuedAt($now)
                     ->setClaim('user', $user)
                     ->withHeader('jki', '1234')
                     ->getToken($signer, $key);

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame(['https://client.abc.com'], $token->claims()->get("aud"));
        self::assertSame('https://api.abc.com', $token->claims()->get("iss"));
        self::assertSame($user, $token->claims()->get('user'));
    }

    public function testHS256Check(): void
    {
        $signer = new HS256();
        $key    = InMemory::base64Encoded('FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M=');

        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
              . 'ZQfnc_iFebE--gXmnhJrqMXv3GWdH9uvdkFXTgBcMFw';

        $token = (new Parser())->parse((string) $data);
        self::assertSame('world', $token->claims()->get('hello'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, $key);
        self::assertTrue($verify);
    }

    public function testHS256Check3(): void
    {
        $signer   = new HS256();
        $key      = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
        $tokenStr = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("joe", $token->claims()->get('iss'));
        self::assertSame(1300819380, $token->claims()->get('exp')->getTimestamp());

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::hexEncoded($key));
        self::assertTrue($verify);
    }

    public function testHS384Check(): void
    {
        $signer   = new HS384();
        $key      = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
        $tokenStr = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("joe", $token->claims()->get('iss'));
        self::assertSame(1300819380, $token->claims()->get('exp')->getTimestamp());

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::hexEncoded($key));
        self::assertTrue($verify);
    }

    public function testHS512Check(): void
    {
        $signer   = new HS512();
        $key      = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
        $tokenStr = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("joe", $token->claims()->get('iss'));
        self::assertSame(1300819380, $token->claims()->get('exp')->getTimestamp());

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::hexEncoded($key));
        self::assertTrue($verify);
    }

    public function testHS256Check2(): void
    {
        $signer = new HS256();
        $key    = InMemory::base64Encoded('FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M=');

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, $key);
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, $key);
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testHS384Check2(): void
    {
        $signer = new HS384();
        $key    = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::hexEncoded($key));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);
        self::assertTrue(strlen((string) $token) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::hexEncoded($key));
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testHS512Check2(): void
    {
        $signer = new HS512();
        $key    = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::hexEncoded($key));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::hexEncoded($key));
        self::assertSame("joe", $token->claims()->get('iss'));
    }
}
