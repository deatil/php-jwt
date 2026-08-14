<?php
declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;

use DateTimeImmutable;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Facade;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\None;
use Deatil\JWT\Signer\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

class NoneTokenTest extends TestCase
{
    public function testBuilderGenerateToken(): void
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new None();
        $key    = InMemory::empty();

        $token = (new Builder())->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->permittedFor('https://client2.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->issuedAt($now)
                         ->setClaim('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($signer, $key);

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame('https://api.abc.com', $token->claims()->get("iss"));
        self::assertSame($user, $token->claims()->get('user'));

        self::assertSame(
            ['https://client.abc.com', 'https://client2.abc.com'],
            $token->claims()->get("aud"),
        );
    }
    
    public function testNoneCheck(): void
    {
        $signer = new None();
        $key    = InMemory::empty();

        $data = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        $token = (new Parser())->parse((string) $data);

        self::assertSame("joe", $token->claims()->get('iss'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, $key);
        self::assertTrue($verify);
    }
    
    public function testNoneCheck2(): void
    {
        $signer = new None();
        $key    = "";

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
