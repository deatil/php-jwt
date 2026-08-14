<?php
declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;

use DateTimeImmutable;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Facade;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Rsa\RS256;
use Deatil\JWT\Signer\Rsa\RS384;
use Deatil\JWT\Signer\Rsa\RS512;
use Deatil\JWT\Signer\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

use function assert;

class RsaTokenTest extends TestCase
{
    public function testBuilderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $now    = new DateTimeImmutable();
        $signer = new RS256();
        $key    = InMemory::plainText('testing');
        
        $builder = (new Builder())
            ->identifiedBy('1')
            ->issuedAt($now)
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:');

        $void = $builder->getToken($signer, $key);
    }

    public function testBuilderGenerateToken(): void
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];

        $now    = new DateTimeImmutable();
        $signer = new RS256();
        $key    = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----";

        $token = (new Builder())->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->permittedFor('https://client2.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->issuedAt($now)
                         ->withClaim('user', $user)
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
        $signer = new RS256();
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFE
ZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqab
vJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUII
ZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+n
wRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd
9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----";

        $tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("bar", $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testRS256Check(): void
    {
        $signer = new RS256();
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDt
nSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAa
hlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNl
X2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJz
QBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1A
uTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7w
IDAQAB
-----END RSA PUBLIC KEY-----";

        $tokenStr =  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("bar", $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testRS384Check(): void
    {
        $signer = new RS384();
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38x
UfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9A
XwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcK
JzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462y
EWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----";

        $tokenStr =  "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.W-jEzRfBigtCWsinvVVuldiuilzVdU5ty0MvpLaSaqK9PlAWWlDQ1VIQ_qSKzwL5IXaZkvZFJXT3yL3n7OUVu7zCNJzdwznbC8Z-b0z2lYvcklJYi2VOFRcGbJtXUqgjk2oGsiqUMUMOLP70TTefkpsgqDxbRh9CDUfpOJgW-dU7cmgaoswe3wjUAUi6B6G2YEaiuXC0XScQYSYVKIzgKXJV8Zw-7AN_DBUI4GkTpsvQ9fVVjZM9csQiEXhYekyrKu1nu_POpQonGd8yqkIyXPECNmmqH5jH4sFiF67XhD7_JpkvLziBpI-uh86evBUadmHhb9Otqw3uV3NTaXLzJw";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("bar", $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testRS512Check(): void
    {
        $signer = new RS512();
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8R
DtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxz
HzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn2
0ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHh
R+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXH
I3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5
LdYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----";

        $tokenStr =  "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ";

        $token = (new Parser())->parse((string) $tokenStr);

        self::assertSame("bar", $token->claims()->get('foo'));

        $validation = new Validator();
        $verify = $validation->verify($token, $signer, InMemory::plainText($pubkey));
        self::assertTrue($verify);
    }

    public function testRS256Check2(): void
    {
        // pkcs1 pubkey
        $signer = new RS256();
        $prikey = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----";
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFE
ZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqab
vJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUII
ZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+n
wRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd
9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----";

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

    public function testRS512Check2(): void
    {
        $signer = new RS512();
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8R
DtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxz
HzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn2
0ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHh
R+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXH
I3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5
LdYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----";

        $tokenStr =  "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ";

        $token = Facade::parse($signer, $tokenStr, InMemory::plainText($pubkey));
        self::assertSame("bar", $token->claims()->get('foo'));
    }

}
