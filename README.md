# nginx-s3-gateway_с

`nginx-s3-gateway_с` — HTTP-модуль NGINX на C для S3-шлюза.  
Модуль формирует S3 URI, генерирует AWS SigV2/SigV4 подписи, управляет внутренними ветками `location`, фильтрует ответы листинга и обновляет временные AWS credentials.

## Что настраивается в модуле

### Контент-режимы (`s3_gateway_content`)
- `redirectToS3`
- `trailslashControl`
- `loadContent`
- `fetchCredentials`

### HTTP-переменные модуля
- `$s3auth`
- `$awsSessionToken`
- `$s3uri`
- `$httpDate`
- `$awsDate`
- `$awsPayloadHash`

### Фильтры
- `s3_gateway_header_filter on;`
- `s3_gateway_body_filter on;`

## Требования

- исходники NGINX (в этом репозитории: `nginx/`)
- компилятор C и `make`
- OpenSSL (`libcrypto`, `libssl`)
- libcurl

Примечание: в `nginx-s3-gateway_с/config` зашит `-L/opt/local/lib`. Если библиотеки лежат в другом пути, поправьте `config`.

## Сборка динамического модуля

```bash
cd nginx
./auto/configure --with-compat --add-dynamic-module="$PWD/../nginx-s3-gateway_с"
make modules
```

Результат сборки:
- `nginx/objs/ngx_http_s3_gateway_c_module.so`

## Обязательные переменные окружения

- `S3_BUCKET_NAME`
- `S3_SERVER`
- `S3_SERVER_PROTO`
- `S3_SERVER_PORT`
- `S3_REGION`
- `AWS_SIGS_VERSION` (`2` или `4`)
- `S3_STYLE` (`path` или `virtual`)

## Опциональные переменные окружения

- `S3_SERVICE` (по умолчанию `s3`)
- `DEBUG`
- `ALLOW_DIRECTORY_LIST`
- `PROVIDE_INDEX_PAGE`
- `APPEND_SLASH_FOR_POSSIBLE_DIRECTORY`
- `FOUR_O_FOUR_ON_EMPTY_BUCKET`
- `HEADER_PREFIXES_TO_STRIP`
- `HEADER_PREFIXES_ALLOWED`

### Статические credentials (если используете их)
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

### Временные credentials (если используете metadata/STS)
- `AWS_CREDENTIALS_TEMP_FILE`
- `TMPDIR`
- `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- `AWS_WEB_IDENTITY_TOKEN_FILE`
- `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`
- `AWS_ROLE_ARN`
- `AWS_ROLE_SESSION_NAME`
- `STS_ENDPOINT`
- `AWS_STS_REGIONAL_ENDPOINTS`
- `AWS_REGION`

## Минимальная схема nginx.conf

В `main`-контексте:

```nginx
load_module modules/ngx_http_s3_gateway_c_module.so;

env S3_BUCKET_NAME;
env S3_SERVER;
env S3_SERVER_PROTO;
env S3_SERVER_PORT;
env S3_REGION;
env AWS_SIGS_VERSION;
env S3_STYLE;
env S3_SERVICE;
env DEBUG;
env ALLOW_DIRECTORY_LIST;
env PROVIDE_INDEX_PAGE;
env APPEND_SLASH_FOR_POSSIBLE_DIRECTORY;
env FOUR_O_FOUR_ON_EMPTY_BUCKET;
env HEADER_PREFIXES_TO_STRIP;
env HEADER_PREFIXES_ALLOWED;
env AWS_ACCESS_KEY_ID;
env AWS_SECRET_ACCESS_KEY;
env AWS_SESSION_TOKEN;
env AWS_CREDENTIALS_TEMP_FILE;
env TMPDIR;
env AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;
env AWS_WEB_IDENTITY_TOKEN_FILE;
env AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE;
env AWS_ROLE_ARN;
env AWS_ROLE_SESSION_NAME;
env STS_ENDPOINT;
env AWS_STS_REGIONAL_ENDPOINTS;
env AWS_REGION;
```

В `http`/`server`-контексте:

```nginx
# путь запроса без query/fragment
map $request_uri $uri_path {
    "~^(?P<path>.*?)(\\?.*)*$" $path;
}

# значения нужны для логики index/listing
set $forIndexPage true;
set $indexIsEmpty true;

# для OSS обычно 0, для Plus можно 1 с keyval
set $cache_signing_key_enabled 0;
set $cache_instance_credentials_enabled 0;

# заглушки под кэш-значения (или keyval в NGINX Plus)
map $request_uri $instance_credential_json { default ""; }
map $request_uri $signing_key_hash { default ""; }

# Host для подписи/проксирования
# virtual style: <bucket>.<S3_SERVER>
# path style: <S3_SERVER>
set $s3_host "example-bucket.s3.us-east-1.amazonaws.com";

location / {
    auth_request /aws/credentials/retrieve;
    s3_gateway_content redirectToS3;
}

location /aws/credentials/retrieve {
    internal;
    s3_gateway_content fetchCredentials;
}

location @s3 {
    proxy_set_header Authorization $s3auth;
    proxy_set_header X-Amz-Security-Token $awsSessionToken;
    proxy_set_header Host $s3_host;
    proxy_pass https://storage_urls$s3uri;
}

location @s3PreListing {
    proxy_set_header Authorization $s3auth;
    proxy_set_header X-Amz-Security-Token $awsSessionToken;
    proxy_set_header Host $s3_host;
    s3_gateway_header_filter on;
    s3_gateway_body_filter on;
    s3_gateway_content loadContent;
}

location @s3Directory {
    set $forIndexPage false;
    proxy_set_header Authorization $s3auth;
    proxy_set_header X-Amz-Security-Token $awsSessionToken;
    proxy_set_header Host $s3_host;
    proxy_pass https://storage_urls$s3uri;
}

location @trailslashControl {
    s3_gateway_content trailslashControl;
}
```

В примере выше предполагается, что upstream `storage_urls` уже объявлен в `http`-контексте.

Для SigV2 и SigV4 добавляйте соответствующие заголовки:

- SigV2:
```nginx
proxy_set_header Date $httpDate;
```

- SigV4:
```nginx
proxy_set_header x-amz-date $awsDate;
proxy_set_header x-amz-content-sha256 $awsPayloadHash;
```

Полный пример блоков `location`:  
`nginx-s3-gateway_с/examples/nginx-c-module-snippet.conf`

## Запуск NGINX

```bash
cd nginx
objs/nginx -p "$PWD" -c conf/nginx.conf
```

Перезагрузка/остановка:

```bash
cd nginx
objs/nginx -p "$PWD" -s reload
objs/nginx -p "$PWD" -s stop
```

## Быстрая проверка

```bash
curl -i http://127.0.0.1/health
curl -I http://127.0.0.1/some/object.txt
curl -I http://127.0.0.1/some/prefix/
curl -i -X POST http://127.0.0.1/some/object.txt
```

Ожидаемо:
- `GET/HEAD` обрабатываются через S3-маршруты
- не-read-only методы получают `405`

## Тесты

```bash
bash nginx-s3-gateway_с/test/perl/run.sh
```

Описание тестов: `nginx-s3-gateway_с/test/perl/README.md`

## Ограничения

- Модуль ориентирован на read-only сценарии (`GET`/`HEAD`).
- Запросы к metadata/STS выполняются синхронно через libcurl.
- Значения дат для подписи инициализируются при старте или reload NGINX.
