<?php

declare(strict_types=1);

namespace Deatil\JWT;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Contracts\Signer;
use Deatil\JWT\Contracts\PayloadToken;
use Deatil\JWT\Encoding\JoseEncoder;
use Deatil\JWT\Format\ChainedFormatter;
use Deatil\JWT\Exception\InvalidTokenStructure;

/**
 * This class have sign and parse function
 */
final class Facade
{
    /**
     * Sign claims function
     *
     * @param Signer $signer
     * @param array  $claims
     * @param Key    $signingKey
     *
     * @return PayloadToken
     */
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

    /**
     * Parse token function
     *
     * @param Signer $signer
     * @param string $tokenString
     * @param Key    $key
     *
     * @return PayloadToken
     */
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
