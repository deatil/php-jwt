<?php
declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;

use DateTimeImmutable;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Hmac\Sha256;
use Deatil\JWT\Signer\Key\InMemory;

use function assert;

class HmacTokenTest extends TestCase
{
    public function testBuilder(): void
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new Sha256();
        $key    = InMemory::plainText('testing');

        $token = (new Builder())->identifiedBy('1')
                     ->permittedFor('https://client.abc.com')
                     ->issuedBy('https://api.abc.com')
                     ->issuedAt($now)
                     ->withClaim('user', $user)
                     ->withHeader('jki', '1234')
                     ->getToken($signer, $key);

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame(['https://client.abc.com'], $token->claims()->get("aud"));
        self::assertSame('https://api.abc.com', $token->claims()->get("iss"));
        self::assertSame($user, $token->claims()->get('user'));
    }

    public function testParser(): void
    {
        $signer = new Sha256();
        $key    = InMemory::base64Encoded('FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M=');

        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
              . 'ZQfnc_iFebE--gXmnhJrqMXv3GWdH9uvdkFXTgBcMFw';

        $token = (new Parser())->parse((string) $data);
        self::assertSame('world', $token->claims()->get('hello'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, $key);
        self::assertTrue($verify);
    }
}
