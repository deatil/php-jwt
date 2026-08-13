<?php

declare(strict_types=1);

namespace Deatil\JWT\Contracts;

use DateTimeImmutable;

interface Clock
{
    public function now(): DateTimeImmutable;
}
