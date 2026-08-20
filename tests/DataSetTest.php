<?php

declare(strict_types=1);

namespace Deatil\JWT\Tests;

use PHPUnit\Framework\TestCase;
use Deatil\JWT\DataSet;

class DataSetTest extends TestCase
{
    public function testDataSet(): void
    {
        $claims = [
            "iss" => "joe",
            "exp" => 1300819380,
            "http://example.com/is_root" => true,
        ];

        $ds = new DataSet($claims, json_encode($claims));
        self::assertSame("joe", $ds->get('iss'));
        self::assertSame("default_val", $ds->get('iss22', 'default_val'));
        self::assertTrue($ds->has('exp'));
        self::assertFalse($ds->has('exp22'));
        self::assertSame($claims, $ds->all());

        $encoded = '{"iss":"joe","exp":1300819380,"http:\/\/example.com\/is_root":true}';
        self::assertSame($encoded, $ds->toString());
        self::assertSame($encoded, (string) $ds);
    }
}
