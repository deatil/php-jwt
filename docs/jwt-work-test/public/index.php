<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;
use Slim\Factory\ServerRequestCreatorFactory;
use Deatil\JWT\Facade;
use Deatil\JWT\Signer\Hmac\HS256;
use Deatil\JWT\Key\InMemory;
use Deatil\JWT\Validator;
use Deatil\JWT\ValidationData;

require __DIR__ . '/../vendor/autoload.php';

AppFactory::setSlimHttpDecoratorsAutomaticDetection(false);
ServerRequestCreatorFactory::setSlimHttpDecoratorsAutomaticDetection(false);

$app = AppFactory::create();

$app->addRoutingMiddleware();
$app->addBodyParsingMiddleware();

// > curl -X GET php-jwt.php1000.com.cn/
$app->get('/', function (Request $request, Response $response, $args) {
    $response->getBody()->write("Hello php-jwt!");

    return $response;
});

// > curl -X GET php-jwt.php1000.com.cn/hi/php-jwt
$app->get('/hi/{name}', function ($request, $response, array $args) {
    $name = $args['name'] ?? "";

    $response->getBody()->write("hi {$name}!");

    return $response;
});

// > curl -X POST -H "Content-Type: application/json" -d '{"name":"jwt","pass":"123"}' php-jwt.php1000.com.cn/login
$app->post('/login', function (Request $request, Response $response, $args) {
    // $body = $request->getBody()->getContents();
    // $data = json_decode($body, true);
    $data = $request->getParsedBody();

    $pass = $data['pass'] ?? "";
    $name = $data['name'] ?? "";

    if (empty($pass) || empty($name)) {
        $response->getBody()->write("pass or name empty.");

        return $response;
    }

    $tokenStr = gen_token($name);

    $response->getBody()->write("token: {$tokenStr}");

    return $response;
});

$auth_middlewdare = function ($request, $handler) use ($app) {
    $auth = $request->getHeaderLine('Authorization');
    if (! $auth) {
        $response = $app->getResponseFactory()->createResponse();
        $response->getBody()->write('Unauthorized');

        return $response;
    }

    if (substr($auth, 0, 7) != "Bearer ") {
        $response = $app->getResponseFactory()->createResponse();
        $response->getBody()->write('token is required');

        return $response;
    }

    $token = substr($auth, 7);
    if (empty($token)) {
        $response = $app->getResponseFactory()->createResponse();
        $response->getBody()->write('token is empty');

        return $response;
    }

    try {
        $user_id = parse_token($token);
    } catch (Exception $e) {
        $response = $app->getResponseFactory()->createResponse();
        $response->getBody()->write('token parse fail.'.$e->getMessage());

        return $response;
    }

    $request = $request->withAttribute("uid", $user_id);

    return $handler->handle($request);
};

$app->group('', function (RouteCollectorProxy $group) {
    // > curl -X GET -H "X-JWT: token" php-jwt.php1000.com.cn/user/profile
    // > curl -X GET -H "Authorization: token" php-jwt.php1000.com.cn/user/profile
    // > curl -X GET -H "Authorization: Bearer token" php-jwt.php1000.com.cn/user/profile
    // > curl -X GET -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3ODY3NzM3MjIsImV4cCI6MTc4OTM2NTcyMiwiYXVkIjoiZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiand0In0.kIy5PBMfE6muXFyHXtwSuMjLb-UA8HqWq-sIdPOXZnA" php-jwt.php1000.com.cn/user/profile
    $group->get('/user/profile', function ($request, $response, array $args) {
        $user_id = $request->getAttribute("uid");

        $response->getBody()->write("uid: {$user_id}");

        return $response;
    });
})->add($auth_middlewdare);

$app->run();

function get_key()
{
    $key = "FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M=";

    return $key;
}

function gen_token($name)
{
    $signer = new HS256();

    $keyStr = get_key();
    $key    = InMemory::base64Encoded($keyStr);

    $t      = new DateTimeImmutable();
    $claims = [
        "iat" => $t,
        "exp" => $t->modify('+30 day'),
        "aud" => ["example.com"],
        "user_id" => $name,
    ];

    $token = Facade::sign($signer, $claims, $key);
    $tokenStr = $token->toString();

    return $tokenStr;
}

function parse_token($tokenStr)
{
    $signer = new HS256();

    $keyStr = get_key();
    $key    = InMemory::base64Encoded($keyStr);

    $token = Facade::parse($signer, $tokenStr, $key);

    $now = new DateTimeImmutable();

    $data = new ValidationData($now, 20);
    $data->permittedFor("example.com");

    $validation = new Validator();
    if (! $validation->validate($token, $data)) {
        throw new Exception("token validate fail");
    }

    $uid = $token->claims()->get('user_id');

    return $uid;
}
