## PHP-JWT 

A JWT (JSON Web Token) library for php.


### Dependencies

- PHP >= 8.1.0
- OpenSSL Extension
- sodium Extension


### What the heck is a JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about reserved keys and the proper way to add your own.


### What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are HMAC SHA, RSA, RSA-PSS, and ECDSA, though hooks are present for adding your own.


## Installation

you can install it using [Composer](http://getcomposer.org).

```shell
composer require deatil/php-jwt
```


### Get Starting

~~~php
use DateTimeImmutable;
use Deatil\JWT\Builder;
use Deatil\JWT\Parser;
use Deatil\JWT\Validator;
use Deatil\JWT\Signer\Hmac\HS256;
use Deatil\JWT\Signer\Key\InMemory;

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

// ouput:
// make token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.CjlHUxjA0Z78-klPuDgGNjbK29ZiEIEh-D4Gnm5JkQ4
echo "make token: {$tokenStr}";

$token = Facade::parse($signer, $tokenStr, $key);
$iss = $token->claims()->get('iss');

// ouput:
// token iss: joe
echo "token iss: {$iss}";
~~~


### Token Validator

~~~php
use DateTimeImmutable;
use Deatil\JWT\Validator;
use Deatil\JWT\ValidationData;

$now = new DateTimeImmutable();

$data = new ValidationData(); // It will use the current time to validate (iat, nbf and exp)
$data->issuedBy('http://example.com');
$data->permittedFor('http://example.org');
$data->identifiedBy('4f1g23a12aa');

$validation = new Validator();

var_dump($validation->validate($token, $data)); // false, because token cannot be used before now() + 60

$data->currentTime($now->modify('+61 seconds')); // changing the validation time to future

var_dump($validation->validate($token, $data)); // true, because current time is between "nbf" and "exp" claims

$data->currentTime($now->modify('+4000 seconds')); // changing the validation time to future

var_dump($validation->validate($token, $data)); // false, because token is expired since current time is greater than exp

// We can also use the $leeway parameter to deal with clock skew (see notes below)
// If token's claimed now is invalid but the difference between that and the validation time is less than $leeway, 
// then token is still considered valid
$dataWithLeeway = new ValidationData($now, 20); 
$dataWithLeeway->issuedBy('http://example.com');
$dataWithLeeway->permittedFor('http://example.org');
$dataWithLeeway->identifiedBy('4f1g23a12aa');

var_dump($validation->validate($token, $dataWithLeeway)); // false, because token can't be used before now() + 60, not within leeway

$dataWithLeeway->currentTime($now->modify('+51 seconds')); // changing the validation time to future

var_dump($validation->validate($token, $dataWithLeeway)); // true, because current time plus leeway is between "nbf" and "exp" claims

$dataWithLeeway->currentTime($now->modify('+3610 seconds')); // changing the validation time to future but within leeway

var_dump($validation->validate($token, $dataWithLeeway)); // true, because current time - 20 seconds leeway is less than exp

$dataWithLeeway->currentTime($now->modify('+4000 seconds')); // changing the validation time to future outside of leeway

var_dump($validation->validate($token, $dataWithLeeway)); // false, because token is expired since current time is greater than exp
~~~


### Signing Methods

The JWT library have signing methods:

 - `ES256`: Deatil\JWT\Signer\Ecdsa\ES256
 - `ES384`: Deatil\JWT\Signer\Ecdsa\ES384
 - `ES512`: Deatil\JWT\Signer\Ecdsa\ES512
 - `ES256K`: Deatil\JWT\Signer\Ecdsa\ES256K
 
 - `EdDSA`: Deatil\JWT\Signer\Eddsa
 - `ED25519`: Deatil\JWT\Signer\Ed25519

 - `RS256`: Deatil\JWT\Signer\Rsa\RS256
 - `RS384`: Deatil\JWT\Signer\Rsa\RS384
 - `RS512`: Deatil\JWT\Signer\Rsa\RS512

 - `HS256`: Deatil\JWT\Signer\Hmac\HS256
 - `HS384`: Deatil\JWT\Signer\Hmac\HS384
 - `HS512`: Deatil\JWT\Signer\Hmac\HS512

 - `BLAKE2B`: Deatil\JWT\Signer\Blake2b

 - `none`: Deatil\JWT\Signer\None


### Sign PublicKey

ECDSA PublicKey:
~~~php
use Deatil\JWT\Signer\Key\InMemory;

// from key pem
$prikey = InMemory::plainText("-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----");
$pubkey = InMemory::plainText("-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----");

// from key pem file, have pass and $pass need set
$prikey = InMemory::plainText(__DIR__ . '/_keys/ecdsa/private.key', $pass);
$pubkey = InMemory::plainText(__DIR__ . '/_keys/ecdsa/pubkey.key');
~~~

EdDSA PublicKey:
~~~php
use Deatil\JWT\Signer\Key\InMemory;

// from key bytes
$prikey = InMemory::base64Encoded("...");
$pubkey = InMemory::base64Encoded("...");
~~~

RSA PublicKey:
~~~php
use Deatil\JWT\Signer\Key\InMemory;

// from key pem
$prikey = InMemory::plainText("-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----");
$pubkey = InMemory::plainText("-----BEGIN RSA PUBLIC KEY-----
...
-----END RSA PUBLIC KEY-----");

// from key pem file, have pass and $pass need set
$prikey = InMemory::plainText(__DIR__ . '/_keys/rsa/private.key', $pass);
$pubkey = InMemory::plainText(__DIR__ . '/_keys/rsa/pubkey.key');
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
