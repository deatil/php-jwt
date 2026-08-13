<?php

declare (strict_types = 1);

namespace Deatil\JWT;

use Closure;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Contracts\Clock;
use Deatil\JWT\Contracts\Signer;
use Deatil\JWT\Contracts\UnencryptedToken;
use Deatil\JWT\Clock\SystemClock;
use Deatil\JWT\Encoding\JoseEncoder;
use Deatil\JWT\Format\ChainedFormatter;
use Deatil\JWT\Claim\Factory as ClaimFactory;

use function assert;

final class Facade
{
    private readonly Parser $parser;

    private readonly Clock  $clock;
    
    public function __construct(
        ?Parser $parser = null,
        ?Clock  $clock  = null,
    ) {
        $this->parser = $parser ?? new Parser(new JoseEncoder(), new ClaimFactory());
        $this->clock  = $clock ?? SystemClock::fromSystemTimezone();
    }

    public function issue(
        Signer  $signer,
        Key     $signingKey,
        Closure $customiseBuilder,
    ): UnencryptedToken {
        $builder = new Builder(
            new JoseEncoder(), 
            new ClaimFactory(),
            ChainedFormatter::withUnixTimestampDates()
        );

        $now = $this->clock->now();
        $builder
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+5 minutes'));

        return $customiseBuilder($builder, $now)->getToken($signer, $signingKey);
    }

    /** 
     * @param non-empty-string $jwt 
     */
    public function parse(string $jwt): UnencryptedToken 
    {
        $token = $this->parser->parse($jwt);
        assert($token instanceof UnencryptedToken);

        return $token;
    }
}
