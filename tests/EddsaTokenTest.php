<?php
declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;

use DateTimeImmutable;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Eddsa;
use Deatil\JWT\Signer\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

use function assert;

class EddsaTokenTest extends TestCase
{
    public function testBuilderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $now    = new DateTimeImmutable();
        $signer = new Eddsa();
        $key    = InMemory::plainText('testing');
        
        $builder = (new Builder())
            ->identifiedBy('1')
            ->issuedAt($now)
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $void = $builder->getToken($signer, $key);
    }

    public function testBuilderGenerateToken(): void
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new Eddsa();
        $key    = InMemory::base64Encoded('K3NWT0XqaH+4jgi42gQmHnFE+HTPVhFYi3u4DFJ3OpRHRMt/aGRBoKD/Pt5H/iYgGCla7Q04CdjOUpLSrjZhtg==');

        $token = (new Builder())->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->permittedFor('https://client2.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->issuedAt($now)
                         ->withClaim('user', $user)
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
    
    public function testParser(): void
    {
        $signer = new Eddsa();
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
}
