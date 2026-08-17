<?php

declare (strict_types = 1);

namespace Deatil\JWT\Claim;

use Deatil\JWT\Contracts\Claim;
use Deatil\JWT\Contracts\Validatable;
use Deatil\JWT\Contracts\ValidationData;

/**
 * Validatable claim that checks if value is lesser or equals to the given data
 */
class LesserOrEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(ValidationData $data): bool
    {
        if ($data->has($this->getName())) {
            return $this->getValue() <= $data->get($this->getName());
        }

        return true;
    }
}
