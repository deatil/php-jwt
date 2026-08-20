<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests\Signer;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Signer\Rsa\RS256;
use Deatil\JWT\Signer\Rsa\RS384;
use Deatil\JWT\Signer\Rsa\RS512;

class RsaTest extends TestCase
{
    public function testRS256(): void
    {
        $msg  = "test-data";
        $sign = "daad532f14e43670a1917de35c7bc86a99c5e5e436d8644cc8150859d2b8851a5f178fb91d694c9e39d33f444a6e4690d71814090166586e5d39d1f470c210410f1b1ecbee2ac8339ab842e218f82e9a75b46257965e31b20c20a8d69c5f802381ef09eced9fb64076af765e256882510917863a2aa552ca95a451b68d82bea75d86ef2a7e003abe1a85b5e265d43791f90b1eef5387c4dcdcd34e4fe59f98f13def79bdc5871737c0cfb8b007fe96c494de8048a608893517b602f7ee576c3a3ac7f28ae444264530e37f555509ee122d6251ad0d3e190adc22c33826d7c957a109559c780c352a9ec9155a30873a7e28a323e78d3adcf58aaf8985f40cf21e";

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

        $h = new RS256();

        $algo = $h->getAlgorithmId();
        self::assertSame("RS256", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }

    public function testRS384(): void
    {
        $msg  = "test-data";
        $sign = "43934323c327b98ce99942bbd1e2810cfd38a90b2b402f56cbeaa15bcb5166a79571538c5bf092bf9fbebe62ed15a746e17b5452ba7f6e35eb5dd062852a9b2383722d223a9d429492996ea3db9d547fedbbba7fc3962ec0192f17beaccd6036ef8595b03ce16124ff2a19bf1fed3e170a441bc9a47056dcf91227d7cb24aab0abce6a32acd60a1c174d4633069ce98848e120dff153fde66001e9c57d65b61c51f92f79f3a6d747c0ef5105445827e36e1fe91d5026373a13247fab37255990a7e023d481da6e2484cc50a080bad88dfce9384c19ec9ff7bd9f7fe7c8a3b1451bf66018f614e6132e6349a4c801f6a8963e947d888fc04a69c9da684ddffa09";

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

        $h = new RS384();

        $algo = $h->getAlgorithmId();
        self::assertSame("RS384", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }

    public function testRS512(): void
    {
        $msg  = "test-data";
        $sign = "af9fe27d9965e111cf86e1e1dbe934e9cd9ae1523be0d95ac7a5bf4909c70d260edbe5a1990db2b2800f49d495a0503675edf0f3c7ab5840561184f2ea19193e8daad66dd8e8942c63dc95a9024263ef199eb5b7a13353f39b79d70a96ed375e1984185ff939a35314cd94c28a2925ebc6cacc07ced6b570e8a253a6d248e3c8ca1dd2f34b5c165a738ccb87271f9ad24d1cdb28532dcc62e91803e83e5383ab529c52e2d6268cbb1ba580bcf989716f8cfc639ebd75acd25947e3e3172ab43b08d5a11a7bc478c25bc374834bd85e4f19b96e8284ceaff12f3eebec3df3415609df0d1fb98df88252357414e776c47bc60a66454b7a69b9c866e0ebbf854cdb0577cff5f6655281dd6de39695b2340acde9f27883c51b1ec8d942c9c719916e23662c9f201ef50c85d11f2a23ed788d090274b9eb942505f02b10ff5814dfdf3ba927dcaabb8bd5fb192d596f390d8e5ca42c133ba678ee5460e3bed661cdb9dfb911835e4a3f2bd668645f14c4b45bab2c4c15878fee03f9374f4268633e1ed56aef9a7820e4cb3001b5a2358671f2d43f629b57bc67e996c59ca06796c95790c4eb829755f43327ab284799723e65cee83887cad2f989e40cccd5152ca2fbae72044140ea0b7a2809f37f0007ff528cb35cc454e276b7a4089a8b98962f03da3669416269e0e1946d21dc3bdac070124275c8a3805a5c9199726016ea1346";

        $prikey = "-----BEGIN RSA PRIVATE KEY-----
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
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

        $h = new RS512();

        $algo = $h->getAlgorithmId();
        self::assertSame("RS512", $algo);

        $signed = $h->sign($msg, InMemory::plainText($prikey));
        self::assertTrue(strlen($signed) > 0);

        $veri = $h->verify($signed, $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri);

        $veri2 = $h->verify(hex2bin($sign), $msg, InMemory::plainText($pubkey));
        self::assertTrue($veri2);
    }
}
