<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;
use DateTimeImmutable;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Facade;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\EdDSA;
use Deatil\JWT\Signer\ED25519;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

class EddsaTokenTest extends TestCase
{
    public function testBuilderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $now    = new DateTimeImmutable();
        $signer = new EdDSA();
        $key    = InMemory::plainText('testing');

        $builder = (new Builder())
            ->identifiedBy('1')
            ->issuedAt($now)
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->setClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $void = $builder->getToken($signer, $key);
    }

    public function testBuilderGenerateToken(): void
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new EdDSA();
        $key    = InMemory::base64Encoded('K3NWT0XqaH+4jgi42gQmHnFE+HTPVhFYi3u4DFJ3OpRHRMt/aGRBoKD/Pt5H/iYgGCla7Q04CdjOUpLSrjZhtg==');

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

    public function testEddsaCheck(): void
    {
        $signer = new EdDSA();
        $key    = InMemory::base64Encoded('R0TLf2hkQaCg/z7eR/4mIBgpWu0NOAnYzlKS0q42YbY=');

        $data = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImpraSI6IjEyMzQifQ.eyJqdGkiOiIxIiwiYXVkIjp'
                . 'bImh0dHBzOi8vY2xpZW50LmFiYy5jb20iLCJodHRwczovL2NsaWVudDIuYWJjLmNvbSJdLCJpc3MiOiJ'
                . 'odHRwczovL2FwaS5hYmMuY29tIiwiaWF0IjoxNzg2NjMyNzY3LCJ1c2VyIjp7Im5hbWUiOiJ0ZXN0aW5'
                . 'nIiwiZW1haWwiOiJ0ZXN0aW5nQGFiYy5jb20ifX0.d0VfUtOUGm_8jMdaxwY3C3iIB76csx0eQsrp9Vb'
                . '3aNuhgLpzml10kMdBHXNCdn4xnx2oXacJEZCv-8lpS1IjDA';

        $token = (new Parser())->parse((string) $data);

        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        self::assertSame($user, $token->claims()->get('user'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, $key);
        self::assertTrue($verify);
    }

    public function testEddsaCheck2(): void
    {
        $signer = new EdDSA();
        $prikey = "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
        $pubkey = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::hexEncoded($prikey));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::hexEncoded($pubkey));
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testEddsaCheck3(): void
    {
        $signer = new ED25519();
        $pubkey = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";

        $tokenStr = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw";

        $token = Facade::parse($signer, $tokenStr, InMemory::hexEncoded($pubkey));
        self::assertSame("bar", $token->claims()->get('foo'));
    }
}
