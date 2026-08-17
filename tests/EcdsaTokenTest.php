<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Facade;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Ecdsa\ES256;
use Deatil\JWT\Signer\Ecdsa\ES384;
use Deatil\JWT\Signer\Ecdsa\ES512;
use Deatil\JWT\Signer\Ecdsa\ES256K;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

use const PHP_EOL;

class EcdsaTokenTest extends TestCase
{
    public function testBuilderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $signer = new ES256();
        $key    = InMemory::plainText('testing');

        $builder = (new Builder())
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->setClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:');

        $void = $builder->getToken($signer, $key);
    }

    public function testBuilderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(): void
    {
        $signer = new ES256();
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

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage("This key is not compatible with this signer");

        $void = $builder->getToken($signer, InMemory::plainText($key));
    }

    public function testBuilderCanGenerateAToken(): void
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new ES256();
        $key    = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBGpMoZJ64MMSzuo5JbmXpf9V4qSWdLIl/8RmJLcfn/qoAoGCCqGSM49
AwEHoUQDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpnd0wxa2iFruiI2tsEdGFTLTsy
U+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==
-----END EC PRIVATE KEY-----";

        $token = (new Builder())->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->permittedFor('https://client2.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->issuedAt($now)
                         ->setClaim('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($signer, InMemory::plainText($key));

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame('https://api.abc.com', $token->claims()->get("iss"));
        self::assertSame($user, $token->claims()->get('user'));

        self::assertSame(
            ['https://client.abc.com', 'https://client2.abc.com'],
            $token->claims()->get("aud"),
        );
    }

    public function testParserAndVerifyToken(): void
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
                . 'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
                . 'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
                . 'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        $key = '-----BEGIN PUBLIC KEY-----' . PHP_EOL
               . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
               . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
               . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
               . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
               . '-----END PUBLIC KEY-----';

        $signer = new ES512();

        $token = (new Parser())->parse((string) $data);
        self::assertSame('world', $token->claims()->get('hello'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($key));
        self::assertTrue($verify);
    }

    public function testES256Check(): void
    {
        $pubkey  = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpIfMi7oTcpgtbeQ0kulzYlAKLQS
t1pfOGUHtHvce8MEssueOxCHWJKql/sJ+JrJSfqOu5AWlDqGqp77ZA7JCw==
-----END PUBLIC KEY-----";
        $tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.WDolEPRIhE9t5azDM_iepn9ezk0dIuExOKFYFAdVS1QC3iOyWM__4ZEAiLgCkGuaPo0ftVQCsCYItjKgVZHgGQ";

        $signer = new ES256();

        $token = (new Parser())->parse((string) $tokenStr);
        self::assertSame('bar', $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testES256Check2(): void
    {
        $signer = new ES256();
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

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::plainText($prikey));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::plainText($pubkey));
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testES384Check(): void
    {
        $pubkey  = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzl47hn4Zf+CcpbMbmhMOH8SDl5XtISQ9
QCTg3AvHtyiUjBuTBoSi0D76NiGQHfSCu28kQK83oM8LTIwJxsxPaCF5wpuyXM7s
l+LET6C/HfkTbXO2VYxC/7K4E1qIVgN7
-----END PUBLIC KEY-----";
        $tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.GeAljd7NH1LQ363xqAb7G608EvXX3svYTMwjcmEVnTapGF7Y4puGIVW4TeXsMij9646Gi_HJ3ghAqgHvWh5CMyvQFOQThyVy7CVxhtrn3GFgse1Kz8wOd0_X_XtOvCsF";

        $signer = new ES384();

        $token = (new Parser())->parse((string) $tokenStr);
        self::assertSame('bar', $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testES384Check2(): void
    {
        $signer = new ES384();
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

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::plainText($prikey));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::plainText($pubkey));
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testES512Check(): void
    {
        $pubkey  = "-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB5SlzIESgK4L2JngDSaRUmzpQ+dRq
VP450M4VqKJo7+DE/1K8+LU85DGNYFjSKTBTWCs3M3U+kFnGgr2MfNHzdtAAsGWE
KQ4W+JQKN6yqLz1OcAc8BnzAzF91mGjwoJURLpNZldd0y1ucbL9EmyjqB0LmhokP
FW9ltEEMEvInnLkEKvI=
-----END PUBLIC KEY-----";
        $tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AdHc_BALB2aBPnEl0FLQtOLgJLqmbxgF9npNd19TZTYwqHmZZ0_eizbagmjJVxpImzXSi-DYezLQDbwN_4iJrvlxAILX9SSrsHh0zbkJAjMAIJDMkZ7nfR7KgCNqvyT7JgEN41i6juk1n8uP3edFptYa1QxnLEG4v6_-NJdOl1xQVtZA";

        $signer = new ES512();

        $token = (new Parser())->parse((string) $tokenStr);
        self::assertSame('bar', $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testES512Check2(): void
    {
        $signer = new ES512();
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

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::plainText($prikey));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::plainText($pubkey));
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testES256KCheck(): void
    {
        $pubkey  = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy8wuv6+fXodLPLfhxm132y1R8m4dkng7
tHe7N+sULV2Eth6AxEXQfd+E4nuceR21UNCvQKqxiYwCzVwIKcHe/A==
-----END PUBLIC KEY-----";
        $tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIifQ.Xe92dmU8MrI1d4edE2LEKqSmObZJpkIuz0fERihfn65ikTeeX5zjpyAdlHy9ZSBX8N8sqmJy5fxBTBzV26WvIQ";

        $signer = new ES256K();

        $token = (new Parser())->parse((string) $tokenStr);
        self::assertSame('bar', $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testES256KCheck2(): void
    {
        $signer = new ES256K();
        $prikey = "-----BEGIN PRIVATE KEY-----
MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgxOKd7ezy1P7xuzAMzj/P
yj7AhgZv09A+vDzHo27pAN2gBwYFK4EEAAqhRANCAATLzC6/r59eh0s8t+HGbXfb
LVHybh2SeDu0d7s36xQtXYS2HoDERdB934Tie5x5HbVQ0K9AqrGJjALNXAgpwd78
-----END PRIVATE KEY-----";
        $pubkey = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy8wuv6+fXodLPLfhxm132y1R8m4dkng7
tHe7N+sULV2Eth6AxEXQfd+E4nuceR21UNCvQKqxiYwCzVwIKcHe/A==
-----END PUBLIC KEY-----";

        $t      = new DateTimeImmutable();
        $claims = [
            "iss" => "joe",
            "exp" => $t->setTimestamp(1300819380),
            "http://example.com/is_root" => true,
        ];

        $token = Facade::sign($signer, $claims, InMemory::plainText($prikey));
        $tokenStr = $token->toString();

        self::assertTrue(strlen($tokenStr) > 0);

        $token = Facade::parse($signer, $tokenStr, InMemory::plainText($pubkey));
        self::assertSame("joe", $token->claims()->get('iss'));
    }

    public function testES256KCheck3(): void
    {
        $pubkey  = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy8wuv6+fXodLPLfhxm132y1R8m4dkng7
tHe7N+sULV2Eth6AxEXQfd+E4nuceR21UNCvQKqxiYwCzVwIKcHe/A==
-----END PUBLIC KEY-----";
        $tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIifQ.Xe92dmU8MrI1d4edE2LEKqSmObZJpkIuz0fERihfn65ikTeeX5zjpyAdlHy9ZSBX8N8sqmJy5fxBTBzV26WvIQ";

        $signer = new ES256K();

        $token = Facade::parse($signer, $tokenStr, InMemory::plainText($pubkey));
        self::assertSame('bar', $token->claims()->get('foo'));
    }

}
