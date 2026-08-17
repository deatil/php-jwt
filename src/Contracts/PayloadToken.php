<?php

declare(strict_types=1);

namespace Deatil\JWT\Contracts;

interface PayloadToken extends Token
{
    /**
     * Returns the token claims
     */
    public function claims(): DataSet;

    /**
     * Returns the token signature
     */
    public function signature(): Signature;

    /**
     * Returns the token payload
     *
     * @return non-empty-string
     */
    public function payload(): string;
}
