#!/usr/bin/perl

# fetchCredentials tests for ngx_http_s3_gateway_c_module.
# Focus: with custom STS endpoint configured, missing web-identity token file fails refresh
# and leaves preseeded keyval credentials unchanged.

use warnings;
use strict;

use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }

BEGIN {
    eval {
        require Test::Nginx;
        Test::Nginx->import();
        1;
    } or do {
        plan(skip_all => "Test::Nginx is required for perl nginx tests");
    };
}

select STDERR; $| = 1;
select STDOUT; $| = 1;

$ENV{S3_BUCKET_NAME} = 'bucket-1';
$ENV{S3_SERVER} = 's3.example.internal';
$ENV{S3_SERVER_PROTO} = 'http';
$ENV{S3_SERVER_PORT} = '80';
$ENV{S3_REGION} = 'us-west-2';
$ENV{AWS_SIGS_VERSION} = '4';
$ENV{S3_STYLE} = 'path';
$ENV{ALLOW_DIRECTORY_LIST} = 'false';
$ENV{PROVIDE_INDEX_PAGE} = 'false';
$ENV{APPEND_SLASH_FOR_POSSIBLE_DIRECTORY} = 'false';
$ENV{FOUR_O_FOUR_ON_EMPTY_BUCKET} = 'false';
delete $ENV{AWS_ACCESS_KEY_ID};
delete $ENV{AWS_SECRET_ACCESS_KEY};
delete $ENV{AWS_SESSION_TOKEN};
delete $ENV{AWS_CONTAINER_CREDENTIALS_RELATIVE_URI};
delete $ENV{AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE};
delete $ENV{AWS_STS_REGIONAL_ENDPOINTS};
delete $ENV{AWS_REGION};
$ENV{STS_ENDPOINT} = 'http://127.0.0.1:8081/sts';
$ENV{AWS_WEB_IDENTITY_TOKEN_FILE} = "/definitely/missing/web-token-$$";
$ENV{AWS_ROLE_ARN} = 'arn:aws:iam::123456789012:role/demo';
$ENV{AWS_ROLE_SESSION_NAME} = 'nginx-s3gw-test';

my $module = $ENV{S3GW_MODULE_SO}
    || "$FindBin::Bin/../../../../nginx/objs/ngx_http_s3_gateway_c_module.so";

my $t = Test::Nginx->new()->has(qw/http rewrite/);

my $conf = <<'EOF_CONF';
%%TEST_GLOBALS%%

daemon off;
load_module $module;
env AWS_ACCESS_KEY_ID;
env AWS_SECRET_ACCESS_KEY;
env AWS_SESSION_TOKEN;
env AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;
env AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE;
env AWS_WEB_IDENTITY_TOKEN_FILE;
env AWS_ROLE_ARN;
env AWS_ROLE_SESSION_NAME;
env AWS_STS_REGIONAL_ENDPOINTS;
env AWS_REGION;
env STS_ENDPOINT;
env S3_BUCKET_NAME;
env S3_SERVER;
env S3_SERVER_PROTO;
env S3_SERVER_PORT;
env S3_REGION;
env AWS_SIGS_VERSION;
env S3_STYLE;
env ALLOW_DIRECTORY_LIST;
env PROVIDE_INDEX_PAGE;
env APPEND_SLASH_FOR_POSSIBLE_DIRECTORY;
env FOUR_O_FOUR_ON_EMPTY_BUCKET;

events {}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /fetch {
            set $cache_instance_credentials_enabled 1;
            set $instance_credential_json '{"accessKeyId":"OLD_AK","secretAccessKey":"OLD_SK","sessionToken":"OLD_ST","expiration":"1"}';
            add_header X-CACHED $instance_credential_json always;
            s3_gateway_content fetchCredentials;
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(4);

my $resp = http_get('/fetch');

like($resp, qr/^HTTP\/1\.1 500 /m,
    'missing web-identity token file returns 500 even when STS_ENDPOINT is configured');
like($resp, qr/\r\nContent-Length: 0\r\n/i,
    'error response has empty body');
like($resp, qr/\r\nContent-Type: text\/plain\r\n/i,
    'error response content-type is text/plain');
like($resp, qr/\r\nX-CACHED: \{"accessKeyId":"OLD_AK","secretAccessKey":"OLD_SK","sessionToken":"OLD_ST","expiration":"1"\}\r\n/i,
    'failed refresh does not overwrite preseeded keyval credentials');
