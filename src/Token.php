<?php

declare (strict_types = 1);

namespace Deatil\JWT;

use DateTimeInterface;

use Deatil\JWT\Contracts\Key;
use Deatil\JWT\Contracts\Claim;
use Deatil\JWT\Contracts\Signer;
use Deatil\JWT\Contracts\DataSet;
use Deatil\JWT\Contracts\Signature;
use Deatil\JWT\Contracts\Validatable;
use Deatil\JWT\Contracts\UnencryptedToken;
use Deatil\JWT\Claim\RegisteredClaims;
use Deatil\JWT\Claim\RegisteredHeaders;

final class Token implements UnencryptedToken
{
    private DataSet $headers;

    private DataSet $claims;

    private Signature $signature;

    public function __construct(
        DataSet   $headers,
        DataSet   $claims,
        Signature $signature
    ) {
        $this->headers   = $headers;
        $this->claims    = $claims;
        $this->signature = $signature;
    }

    public function headers(): DataSet
    {
        return $this->headers;
    }

    public function claims(): DataSet
    {
        return $this->claims;
    }

    public function signature(): Signature
    {
        return $this->signature;
    }

    public function payload(): string
    {
        return $this->headers->toString() . '.' . $this->claims->toString();
    }

    public function isPermittedFor(string $audience): bool
    {
        return $this->claims->get(RegisteredClaims::AUDIENCE) === $audience;
    }
    
    public function isIdentifiedBy(string $id): bool
    {
        return $this->claims->get(RegisteredClaims::ID) === $id;
    }

    public function isRelatedTo(string $subject): bool
    {
        return $this->claims->get(RegisteredClaims::SUBJECT) === $subject;
    }

    public function hasBeenIssuedBy(string ...$issuers): bool
    {
        return in_array($this->claims->get(RegisteredClaims::ISSUER), $issuers, true);
    }

    public function hasBeenIssuedBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->get(RegisteredClaims::ISSUED_AT);
    }

    public function isMinimumTimeBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->get(RegisteredClaims::NOT_BEFORE);
    }

    public function isExpired(DateTimeInterface $now): bool
    {
        if (! $this->claims->has(RegisteredClaims::EXPIRATION_TIME)) {
            return false;
        }

        return $now >= $this->claims->get(RegisteredClaims::EXPIRATION_TIME);
    }

    public function toString(): string
    {
        return $this->headers->toString() . '.'
             . $this->claims->toString() . '.'
             . $this->signature->toString();
    }
}
