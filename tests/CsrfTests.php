<?php

namespace Tests;

use bemang\Session\PHPSession;
use bemang\csrf\CsrfMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\MiddlewareInterface;

class CsrfTests extends TestCase
{
    public function setUp()
    {
        require_once(__DIR__ . '/../vendor/autoload.php');
    }
    public function testConstruction()
    {
        $middleware = new CsrfMiddleware(new PHPSession());
        $this->assertInstanceOf(MiddlewareInterface::class, $middleware);
    }
}
