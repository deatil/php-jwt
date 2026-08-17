<?php

declare(strict_types=1);

namespace Deatil\JWT;

use Closure;
use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Contracts\Signer;
use Deatil\JWT\Contracts\PayloadToken;
use Deatil\JWT\Encoding\JoseEncoder;
use Deatil\JWT\Format\ChainedFormatter;
use Deatil\JWT\Exception\InvalidTokenStructure;

use function assert;

final class Facade
{
    public static function sign(
        Signer $signer,
        array $claims,
        Key $signingKey,
    ): PayloadToken {
        $builder = new Builder(
            new JoseEncoder(),
            ChainedFormatter::withUnixTimestampDates()
        );

        foreach ($claims as $key => $claim) {
            $builder->withClaim($key, $claim);
        }

        return $builder->getToken($signer, $signingKey);
    }

    public static function parse(
        Signer $signer,
        string $tokenString,
        Key $key,
    ): PayloadToken {
        $token = (new Parser())->parse($tokenString);

        $validation = new Validator();
        if (! $validation->verify($token, $signer, $key)) {
            throw InvalidTokenStructure::tokenVerifyFail();
        }

        return $token;
    }
}
