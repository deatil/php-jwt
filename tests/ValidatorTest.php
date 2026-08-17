<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Deatil\JWT\Parser;
use Deatil\JWT\Validator;
use Deatil\JWT\ValidationData;
use Deatil\JWT\Key\InMemory;

class ValidatorTest extends TestCase
{
    public function testCheck(): void
    {
        $data = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";

        $token = (new Parser())->parse($data);

        $now = new DateTimeImmutable();

        $data = new ValidationData($now->setTimestamp(1767812388));
        $data->identifiedBy('jti rrr');
        $data->issuedBy('iss');
        $data->permittedFor('example.com');
        $data->relatedTo('sub');

        $validation = new Validator();

        self::assertTrue($validation->validate($token, $data));
    }

    public function testCheck2(): void
    {
        $data = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";

        $token = (new Parser())->parse($data);

        $now = new DateTimeImmutable();

        $data = new ValidationData($now->setTimestamp(1767812388));
        $data->identifiedBy('jti rrr');
        $data->issuedBy('iss');
        $data->permittedFor('example.com');
        $data->relatedTo('sub');
        $data->currentTime($now->setTimestamp(1967812388));

        $validation = new Validator();

        self::assertFalse($validation->validate($token, $data));
    }

    public function testCheck3(): void
    {
        $data = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";

        $token = (new Parser())->parse($data);

        $now = new DateTimeImmutable();

        $data = new ValidationData($now->setTimestamp(1767842409), 20);
        $data->identifiedBy('jti rrr');
        $data->issuedBy('iss');
        $data->permittedFor('example.com');
        $data->relatedTo('sub');

        $validation = new Validator();

        self::assertFalse($validation->validate($token, $data));
    }

    public function testCheck31(): void
    {
        $data = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";

        $token = (new Parser())->parse($data);

        $now = new DateTimeImmutable();

        $data = new ValidationData($now->setTimestamp(1767842409));
        $data->identifiedBy('jti rrr');
        $data->issuedBy('iss');
        $data->permittedFor('example.com');
        $data->relatedTo('sub');
        $data->leewayFor(20);

        $validation = new Validator();

        self::assertFalse($validation->validate($token, $data));
    }
}
