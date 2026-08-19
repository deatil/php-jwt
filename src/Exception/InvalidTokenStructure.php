<?php

declare(strict_types=1);

namespace Deatil\JWT\Exception;

use InvalidArgumentException;

final class InvalidTokenStructure extends InvalidArgumentException implements Exception
{
    public static function missingOrNotEnoughSeparators(): self
    {
        return new self('The JWT string must have two dots');
    }

    public static function missingHeaderPart(): self
    {
        return new self('The JWT string is missing the Header part');
    }

    public static function missingClaimsPart(): self
    {
        return new self('The JWT string is missing the Claim part');
    }

    public static function missingSignaturePart(): self
    {
        return new self('The JWT string is missing the Signature part');
    }

    public static function tokenVerifyFail(): self
    {
        return new self('The JWT token verify fail');
    }

    public static function arrayExpected(string $part): self
    {
        return new self($part . ' must be an array with non-empty-string keys');
    }

    public static function dateIsNotParseable(string $value): self
    {
        return new self('Value is not in the allowed date format: ' . $value);
    }
}
