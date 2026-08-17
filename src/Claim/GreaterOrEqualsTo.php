<?php

declare(strict_types=1);

namespace Deatil\JWT\Claim;

use Deatil\JWT\Contracts\Claim;
use Deatil\JWT\Contracts\Validatable;
use Deatil\JWT\Contracts\ValidationData;

/**
 * Validatable claim that checks if value is greater or equals the given data
 */
class GreaterOrEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(ValidationData $data): bool
    {
        if ($data->has($this->getName())) {
            return $this->getValue() >= $data->get($this->getName());
        }

        return true;
    }
}
