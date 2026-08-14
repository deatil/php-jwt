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
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Exception\InvalidKeyProvided;

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
            ->setClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

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

    public function testRS384Check2(): void
    {
        // pkcs1 pubkey
        $signer = new RS384();
        $prikey = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArFl9Kb6QL5mZ9HuiEvf9R2RTRc3sz3PfDQDUkMNlp75qpB8i
HmA3Yn+OR4rCtcjX5j138fs6LG5tjlVCyjn6w1DlWJM18fHaRllkDUiq9zdxAXdH
+Yf9TMOuHFbxL+/MOZKyUnRdsS4fnkKA7dEyyCpjew2ffVB7VjD2754GKOcBL2aq
walchkhNEPh0uI5oOuHqk87SiuAM2ZDIb2wd+xI1L36P9HrPrwekoWkAM+Wxnu4G
ApoM87UKEUchiGxlkWEHM0dSM4XThhrXlSLRJN3izEw+8BQK7H8zd/MD/br+2Hr7
SYxpEsi3k4y4HC+RYPt6oDNrFW1irO2sva6TRwIDAQABAoIBADkd4xvtem0780iR
nHG626ZIOkyc5QkPNnFhwBBFoS/JLCA97Rmx+0jaSvWsp8CE0gAMiO6Zunq1Efuk
h+Dq/A60hX0oNC19YEAGKeE5HueU6Q96T1ED308MXmwn6ABh8QV3dz9aLx6j0Xiq
Q34M4U5ytcs3BY8LGATFb2CTtyjgcidzsWVJd5b41KDSUQhFYDXxUfJ0ToWGHCu2
KCImXbcQdKyUKunaEd/p0ghO9AEhVeYAr3CAtKhOJ56boBNKQ1QawBeM1KVRBI9P
sgSMLBxKBI9veNCwuawdd5VJo8e5EdeGBxHDT/OXTG+QdJpbLaz+Clfq1nzCzMTY
DVcv1cECgYEAyMpdDM/PdDq+Fpk7Xuuj9ZAbKIEQueS2gLCUH7jnlvYuQZfLhAyy
GBjI6vaVDh7Go3+oycB8VmVHs2Um9p63LgxOwatBkFmf/F1u9aHH/oD14O8hUhX1
1uqm/VvPPkvvg0AOxbYT897vGsyFZVwS3a9KdaDVx9noz5FnRGYhG2ECgYEA270r
jaTHNv26wYiqT3F933rqTwkcEtoWhurCjSbLQCClh/dB/g44rCdefdvlolTNUATQ
UNYEPVz4rzHkeHvNfZm4mzHxjVm7GkIFpdupLKnMWFzd4gqgZarX/bBYhJRORokW
5oAHh9/IZzgmHtfUeKnJKr1eYyDRLu9KdQigF6cCgYAW9oWzvGRmT32DyhxvG5XR
tJxWgoQuLkjs6MTX5+acbiUWHU0KGgWYGeWIcZDUX5KqCiR8hkXx/302t/+/vqEG
ZCPxpCtIXeedDfZtowXjRk5YXiC6aYaHAKj+WqyV3EtVAFNwKwWXI0zHDNLIp8IE
llJ2p2ErjPFCI8fim6d3oQKBgAL7EPEt8And7T+c0/qZ5oQ2jaEe1YOn87BG1PbH
NPCcwMIUZ4/Dr58eNZjtd7L5BYP1XMIL9SjD7xepTJkZzNLMWAW66rTpJ7GWfa8f
SK8zanM0Z0oerMhURfPKBZlezaUFTQs5Z2C/d193EoVOljJA01rCENq1YkEJu+/U
ex93AoGAH15vFej3Bx9cLBRgDOhnS9Lz7U02q3y0iaPcPM85gWVgQbN8otTvdoE/
tjIDYVtKEopJUCLUkg5j2n3HgluOFvXiz88kdWaARXg5Ai5i0u2Mv0iUr2XZ+xmd
cpfSW47xyzigAlyf50WIgCNexW/bpwlKI4Mx6QF6/hOQoo6NG84=
-----END RSA PRIVATE KEY-----";
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArFl9Kb6QL5mZ9HuiEvf9R2RTRc3sz3PfDQDUkMNlp75qpB8iHmA3
Yn+OR4rCtcjX5j138fs6LG5tjlVCyjn6w1DlWJM18fHaRllkDUiq9zdxAXdH+Yf9
TMOuHFbxL+/MOZKyUnRdsS4fnkKA7dEyyCpjew2ffVB7VjD2754GKOcBL2aqwalc
hkhNEPh0uI5oOuHqk87SiuAM2ZDIb2wd+xI1L36P9HrPrwekoWkAM+Wxnu4GApoM
87UKEUchiGxlkWEHM0dSM4XThhrXlSLRJN3izEw+8BQK7H8zd/MD/br+2Hr7SYxp
Esi3k4y4HC+RYPt6oDNrFW1irO2sva6TRwIDAQAB
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
        // pkcs1 pubkey
        $signer = new RS512();
        $prikey = "-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAsZYeUijvz4Ghg9a9eR+4lGGlB7Iyrck66EJxyP+RKH3izCG1
6gHkD8r3pm6UsJ1EHQZqSsb6GG9n1T67xESZgIsDFj+AzhOgH1pNXbe5FAoyMOLp
3pT2XRs4ck8PEHdKyUHD2WfY52e39WNJ5O1mLY9JYfg7K1ThGeyQ1+f5T8B8U1ZM
iLDv63XullUNjswxY2KEHcb4gOK0GU7fb4ENFOYDqnxjlOlt6gpIM5nRhTp5wR3e
HXQzbJU0rqUIM+2w+a81p+Uda1UcnUGgxdxo/KCtCo5Aj69B+Iti1TLkZ4warYRm
/NLKQN3jmfoaBUyo5C+7p15xghZDto9kNpsPhAdcVVKPQV6RhJizK0ydZSPHycjL
dfhQNWH+G2mI2FMXqM/pwmIxZbmK9EfGisZRmF9k/2kebx/kyXDsCT8fw1LpkeZV
YV1/s5SwpaONlEolbFYFWPV3ukRVN2EYsOM2EeEeDb16Qy0CXHfL8UxErZIe3O42
vIsl50dqXnMC3Ro3sIjPy68Q1sUHYSWDmOrdnodZvQYT+8zYj4LTa/uS0wbheoIt
jz4HK5/vCt7Ffh1jqoT1+9GNlt3DGoH36HYH8fsEgZ11EOiG4GaL1J7YazipHrgF
ZS/7YuZOrHVLUP473odCZkhaZCjb9dOoNxawJqxM9mi2ZVRF8EjTp7QO3EECAwEA
AQKCAgEAp8eq8fjXSXex/3t9G9jKbPYsEy9bDjIWw6UzF7HNlTIKes5GrsYGkJ00
iTvko1CSL9IFzoxbcYaf1Ssl/3LIjFfKHNT2frywBa8tdSPFapePf/yC9NZMRP8Y
v3bORsJOGANYZCjnFwo5FVAvWmiopta/gB4k2PWijvmghzwVojG7xIi+Wk7A/fc3
6TSGUKm+56UGKZP46NxHR7nrA9Aradk/EW3gL6qzO/Fm8cmb2IG80qXDWpSUmTwG
wBIPw/AHyn6s9OlUeDm7hR+iJA3v6u5rTpPDj30HmSknwUIJ5YLLGbEEFE2a5No+
1RUkTGl3D8/BPYnPOBaM9whWp/isGH+3Xw8RQpW8YQgZdqNOTr1U5gs/+Fpsf9s4
1IKuhZC+CQyPUv/ypwZYbkI7O5Y+xuWr1Awy4ON/yFLehmvDfsAB6Q5dJ5fH3eU6
2LbUtXZP02hkuuC+r/Rgy5lIIpxlwZmupyS9TiZi4Wzl+G93lrdQgItPB5uLKDaJ
d2CmzM+/rgmwP9y3Lcei5L2BPhNqnIG4Qewmo4yc31lxaEyuyKUCwsZTBN7bQmge
jemDJISTRAFxBawGiP2OBXX4kWAkNZoRPS5PwzvGWxfyinurQje6SYqXMglZfLPI
xgG2pn0bctD7dLK94WqCu0RyXft3vPtGTVBLWryjh/z0KSNCz6ECggEBAMjhCIcT
xugzE4k/XiRzRCq+Jd7iYR/Dz3emQWHxwJZ5UUAOh02E3NU59sqQupokK2q8LrDM
SFZk27ZNrXwQgWvGxxXybnmDeL+oqQd4m3nPi94Yn8gV5x6QWMbGCK8h9DgS3pP5
2vbE7QsIXeIDpV8HxSGHtTu+NYHilCsMbOAjZVK4pWi1C/DZhVfpiX/WXyoZvRYj
o7xMtYEQGJfRwLq0y1WXhMEf+ybhk9qbRwr5ca4sxWoR12zF12aKqR6+OLxfVOBQ
0rVuxYjx10fe7LXJ2iYfG4OxLBOCEFY9KB4+sY4Y2EFTnm2iusX17xYWbgAzTkdc
mGQ+DI/ZecVek6UCggEBAOJQ3lgP8yC28QvFRdb73y+ly3BdR3E5RuZHvqlJR8hg
8hDVryGEZJp1vDG/2S3+wCowoGVWcEnoAMURLSxXQwNSe8LfxQCD+7wyQhQzJw7g
eYbZhHkLl780m9BULdHsjHeeayw6f0zZ991CCVM3bDWbcnpqzBfu9bHG8N0gXUv/
BL7Xi9Sp7I4Bb5wg4TdpDbc/JCl9H/7hyIAHCqnWd1ZbLGl2nSOfRMR+t444Q5el
XidyIqUvkdAJi7FE6fgH4wsZ3rkAz+r3IgJAUZu3QoxyD+rlUVYL0wcizGsk2VYg
4ayKZxRjAy9YMvHsHwN6r5rx6/mXNcv+T7rx1etl020CggEAUmGfeq4Mq9uOjoHT
XQV8lj7nDxIuHLXUFtCzDbT0c4GLZcbPjGYJntSntolGTcK5n4tPZqhQnkW8qXYP
yMqIGSgrK4AB+ImHcqp7r5mxwXHxfYMBvC/nWex+y/4ZP6GgI4LxjyQvvXYjdJvY
zMEMB/4KxWZ/V+H41ayTcVgmKoG5owQgqeFd5Ud/3P7kqe3Dl2N43WR+WNHoueZc
/55A+RD+Nrrt8bno6Rgn58Y4i3KjQXgQ+iAZBf3ZCa+iDf6bC/3YtCnRUCD+l9v+
mvX8g80lTu8A/LAjUFjN1GA+XLD/ZjQgNCJT3ciX6mmixJ8sO57O4otB4BJmWnQo
8V2JFQKCAQEAzUg5RnvBNy153Alm3ii9O4UR0axqv0MLEpqFURzNZe6545dQMgDb
GFgvCplQsC3htONCumj7la5B9H8uEIhemsbYx90d3ufZEc4srhHwHchzs2Pei8V+
McvQgdm5bi85As/JuuaczeLwt9vMhZVCLCYCYxQ4aIUyi70+gfV3axW5AjqV9aLk
lbKrwFz6rL432L4HWTLMMPAwZCD/BSsqOESfNlKHGua/A9VFPlW+yfEQRIt87YUG
qEPgWD2AVKEiytD+e6VG84STbqNU4wAJ90cHNTQo4Pn8wv5HmfBky4Er8svf0Fg3
bVx9aX+aaheA7fT+7PjBrXXScGoodkt4yQKCAQA4GWFp/75llZVHdizcTWIdz6Ul
HUKms6lLRUJXJnPMQZOL4RlbdM5+VfXf4vHHbICSccyf7zZoZgYu4GWKYnWNhNuF
TxFxa78CpW9LLhuZlOPtuqtcspMMU4LDe5Adk3law3nHrLTvvp2b5CUDfQpoxsn9
cbwoq0vVpnIw2vURKYeJCUB3VSTz4z63dDsdNuiD5MbEW3yk+t9iPKDdLwqJq8/L
lupfCOB9lvR7G4DEj88gbNsv8VJnudCiwU/ZcZ58tLx+InoQcn8DHyjw4J+4D0q/
vpLgokcJibOI3bbCw2GIc7euER5b3HriI2UOVxi/p4O+m17oRDYxMYaXPxAd
-----END RSA PRIVATE KEY-----";
        $pubkey = "-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAsZYeUijvz4Ghg9a9eR+4lGGlB7Iyrck66EJxyP+RKH3izCG16gHk
D8r3pm6UsJ1EHQZqSsb6GG9n1T67xESZgIsDFj+AzhOgH1pNXbe5FAoyMOLp3pT2
XRs4ck8PEHdKyUHD2WfY52e39WNJ5O1mLY9JYfg7K1ThGeyQ1+f5T8B8U1ZMiLDv
63XullUNjswxY2KEHcb4gOK0GU7fb4ENFOYDqnxjlOlt6gpIM5nRhTp5wR3eHXQz
bJU0rqUIM+2w+a81p+Uda1UcnUGgxdxo/KCtCo5Aj69B+Iti1TLkZ4warYRm/NLK
QN3jmfoaBUyo5C+7p15xghZDto9kNpsPhAdcVVKPQV6RhJizK0ydZSPHycjLdfhQ
NWH+G2mI2FMXqM/pwmIxZbmK9EfGisZRmF9k/2kebx/kyXDsCT8fw1LpkeZVYV1/
s5SwpaONlEolbFYFWPV3ukRVN2EYsOM2EeEeDb16Qy0CXHfL8UxErZIe3O42vIsl
50dqXnMC3Ro3sIjPy68Q1sUHYSWDmOrdnodZvQYT+8zYj4LTa/uS0wbheoItjz4H
K5/vCt7Ffh1jqoT1+9GNlt3DGoH36HYH8fsEgZ11EOiG4GaL1J7YazipHrgFZS/7
YuZOrHVLUP473odCZkhaZCjb9dOoNxawJqxM9mi2ZVRF8EjTp7QO3EECAwEAAQ==
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

    public function testRS512Check3(): void
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
