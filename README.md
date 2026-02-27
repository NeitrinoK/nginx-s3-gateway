# nginx-s3-gateway_с

nginx-s3-gateway_c is an NGINX HTTP module written in C for S3 gateway functionality.
The module generates S3 URIs, creates AWS SigV2/SigV4 signatures, manages internal location branches, filters listing responses, and refreshes temporary AWS credentials.

## Module Configuration Options

### Content Modes (s3_gateway_content)
- `redirectToS3`
- `trailslashControl`
- `loadContent`
- `fetchCredentials`

### Module HTTP Variables
- `$s3auth`
- `$awsSessionToken`
- `$s3uri`
- `$httpDate`
- `$awsDate`
- `$awsPayloadHash`

### Filters
- `s3_gateway_header_filter on;`
- `s3_gateway_body_filter on;`

## Build requirements

- NGINX source code (in this repository: nginx/)
- C compiler and make
- OpenSSL (`libcrypto`, `libssl`)
- libcurl

Note: nginx-s3-gateway_c/config hardcodes -L/opt/local/lib. If libraries are in a different path, update config.

## Building the Dynamic Module

```bash
cd nginx
./auto/configure --with-compat --add-dynamic-module="$PWD/../nginx-s3-gateway_с"
make modules
```

Build result:
- `nginx/objs/ngx_http_s3_gateway_c_module.so`

## Required Environment Variables

- `S3_BUCKET_NAME`
- `S3_SERVER`
- `S3_SERVER_PROTO`
- `S3_SERVER_PORT`
- `S3_REGION`
- `AWS_SIGS_VERSION` (`2` или `4`)
- `S3_STYLE` (`path` или `virtual`)

## Optional Environment Variables

- `S3_SERVICE` (по умолчанию `s3`)
- `DEBUG`
- `ALLOW_DIRECTORY_LIST`
- `PROVIDE_INDEX_PAGE`
- `APPEND_SLASH_FOR_POSSIBLE_DIRECTORY`
- `FOUR_O_FOUR_ON_EMPTY_BUCKET`
- `HEADER_PREFIXES_TO_STRIP`
- `HEADER_PREFIXES_ALLOWED`

### Static Credentials (if using them)
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

### Temporary Credentials (if using metadata/STS)
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

## Minimal nginx.conf Schema

In main context:

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

In http/server context:

```nginx
# request path without query/fragment
map $request_uri $uri_path {
    "~^(?P<path>.*?)(\\?.*)*$" $path;
}

# values needed for index/listing logic
set $forIndexPage true;
set $indexIsEmpty true;

# usually 0 for OSS, can be 1 with keyval for Plus
set $cache_signing_key_enabled 0;
set $cache_instance_credentials_enabled 0;

# stubs for cache values (or keyval in NGINX Plus)
map $request_uri $instance_credential_json { default ""; }
map $request_uri $signing_key_hash { default ""; }

# Host for signing/proxying
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

The example above assumes storage_urls upstream is already declared in the http context.

For SigV2 and SigV4, add corresponding headers:

- SigV2:
```nginx
proxy_set_header Date $httpDate;
```

- SigV4:
```nginx
proxy_set_header x-amz-date $awsDate;
proxy_set_header x-amz-content-sha256 $awsPayloadHash;
```

Full example location blocks: 
`nginx-s3-gateway_с/examples/nginx-c-module-snippet.conf`

## Running NGINX

```bash
cd nginx
objs/nginx -p "$PWD" -c conf/nginx.conf
```

Reload/stop:

```bash
cd nginx
objs/nginx -p "$PWD" -s reload
objs/nginx -p "$PWD" -s stop
```

## Quick Test

```bash
curl -i http://127.0.0.1/health
curl -I http://127.0.0.1/some/object.txt
curl -I http://127.0.0.1/some/prefix/
curl -i -X POST http://127.0.0.1/some/object.txt
```

Expected:
- `GET/HEAD` handled via S3 routes
- non-read-only methods return `405`

## Tests

```bash
bash nginx-s3-gateway_с/test/perl/run.sh
```

Test description: `nginx-s3-gateway_с/test/perl/README.md`

## Limitations

- Module focused on read-only scenarios  (`GET`/`HEAD`).
- Metadata/STS requests executed synchronously via libcurl.
- Date values for signing initialized at NGINX start or reload.
