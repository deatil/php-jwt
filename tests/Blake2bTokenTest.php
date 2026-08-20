<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests;

use SodiumException;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Facade;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Blake2b;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

class Blake2bTokenTest extends TestCase
{
    public function testBuilderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $signer = new Blake2b();
        $key    = InMemory::plainText('testing');

        $builder = (new Builder())
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->setClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits, only 56 bits provided');

        $void = $builder->getToken($signer, $key);
    }

    public function testBuilderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(): void
    {
        $signer = new Blake2b();
        $key    = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTvwE87MtgREYL
TL4aHhQo3ZzogmxxvMUsKnPzyxRs1YrXOSOpwN0npsXarBKKVIUMNLfFODp/vnQn
2Zp06N8XG59WAOKwvC4MfxLDQkA+JXggzHlkbVoTN+dUkdYIFqSKuAPGwiWToRK2
SxEhij3rE2FON8jQZvDxZkiP9a4vxJO3OTPQwKredXFiObsXD/c3RtLFhKctjCyH
OIrP0bQEsee/m7JNtG4ry6BPusN6wb+vJo5ieBYPa3c19akNq6q/nYWhplhkkJSu
aOrL5xXEFzI5TvcvnXR568GVcxK8YLfFkdxpsXGt5rAbeh0h/U5kILEAqv8P9PGT
ZpicKbrnAgMBAAECggEAd3yTQEQHR91/ASVfKPHMQns77eCbPVtekFusbugsMHYY
EPdHbqVMpvFvOMRc+f5Tzd15ziq6qBdbCJm8lThLm4iU0z1QrpaiDZ8vgUvDYM5Y
CXoZDli+uZWUTp60/n94fmb0ipZIChScsI2PrzOJWTvobvD/uso8MJydWc8zafQm
uqYzygOfjFZvU4lSfgzpefhpquy0JUy5TiKRmGUnwLb3TtcsVavjsn4QmNwLYgOF
2OE+R12ex3pAKTiRE6FcnE1xFIo1GKhBa2Otgw3MDO6Gg+kn8Q4alKz6C6RRlgaH
R7sYzEfJhsk/GGFTYOzXKQz2lSaStKt9wKCor04RcQKBgQDzPOu5jCTfayUo7xY2
jHtiogHyKLLObt9l3qbwgXnaD6rnxYNvCrA0OMvT+iZXsFZKJkYzJr8ZOxOpPROk
10WdOaefiwUyL5dypueSwlIDwVm+hI4Bs82MajHtzOozh+73wA+aw5rPs84Uix9w
VbbwaVR6qP/BV09yJYS5kQ7fmwKBgQDe2xjywX2d2MC+qzRr+LfU+1+gq0jjhBCX
WHqRN6IECB0xTnXUf9WL/VCoI1/55BhdbbEja+4btYgcXSPmlXBIRKQ4VtFfVmYB
kPXeD8oZ7LyuNdCsbKNe+x1IHXDe6Wfs3L9ulCfXxeIE84wy3fd66mQahyXV9iD9
CkuifMqUpQKBgQCiydHlY1LGJ/o9tA2Ewm5Na6mrvOs2V2Ox1NqbObwoYbX62eiF
53xX5u8bVl5U75JAm+79it/4bd5RtKux9dUETbLOhwcaOFm+hM+VG/IxyzRZ2nMD
1qcpY2U5BpxzknUvYF3RMTop6edxPk7zKpp9ubCtSu+oINvtxAhY/SkcIwKBgGP1
upcImyO2GZ5shLL5eNubdSVILwV+M0LveOqyHYXZbd6z5r5OKKcGFKuWUnJwEU22
6gGNY9wh7M9sJ7JBzX9c6pwqtPcidda2AtJ8GpbOTUOG9/afNBhiYpv6OKqD3w2r
ZmJfKg/qvpqh83zNezgy8nvDqwDxyZI2j/5uIx/RAoGBAMWRmxtv6H2cKhibI/aI
MTJM4QRjyPNxQqvAQsv+oHUbid06VK3JE+9iQyithjcfNOwnCaoO7I7qAj9QEfJS
MZQc/W/4DHJebo2kd11yoXPVTXXOuEwLSKCejBXABBY0MPNuPUmiXeU0O3Tyi37J
TUKzrgcd7NvlA41Y4xKcOqEA
-----END PRIVATE KEY-----";

        $builder = (new Builder())
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->setClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage("unsupported key length");

        $void = $builder->getToken($signer, InMemory::plainText($key));
    }

    public function testBuilderCanGenerateAToken(): void
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new Blake2b();
        $key    = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

        $token = (new Builder())->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->permittedFor('https://client2.abc.com')
            ->issuedBy('https://api.abc.com')
            ->issuedAt($now)
            ->setClaim('user', $user)
            ->withHeader('jki', '1234')
            ->getToken($signer, InMemory::hexEncoded($key));

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame('https://api.abc.com', $token->claims()->get("iss"));
        self::assertSame($user, $token->claims()->get('user'));

        self::assertSame(
            ['https://client.abc.com', 'https://client2.abc.com'],
            $token->claims()->get("aud"),
        );
    }

    public function testBlake2bCheck(): void
    {
        $data = "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb9M";
        $key  = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

        $signer = new Blake2b();

        $token = (new Parser())->parse((string) $data);
        self::assertSame('joe', $token->claims()->get('iss'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::hexEncoded($key));
        self::assertTrue($verify);
    }

    public function testBlake2bCheck2(): void
    {
        $signer = new Blake2b();
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
