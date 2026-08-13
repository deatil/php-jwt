<?php

declare (strict_types = 1);

namespace Deatil\JWT\Contracts;

/**
 * Key
 */
interface Key
{
    /**
     * @return string
     */
    public function getContent(): string;

    /**
     * @return string
     */
    public function getPassphrase(): string;
}
