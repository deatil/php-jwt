### Run 

install dependencies:
```bash
composer install
```

set public to index.

set exmple url:
```
php-jwt.php1000.com.cn
```

### Request

request login:

```bash
curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"name":"jwt","pass":"123"}' \
    php-jwt.php1000.com.cn/login
```

get user info from:

```bash
curl -X GET \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3ODY3NzM3MjIsImV4cCI6MTc4OTM2NTcyMiwiYXVkIjoiZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiand0In0.kIy5PBMfE6muXFyHXtwSuMjLb-UA8HqWq-sIdPOXZnA" \
    php-jwt.php1000.com.cn/user/profile
```
