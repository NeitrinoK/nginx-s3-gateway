#!/usr/bin/perl

# fetchCredentials content-handler tests for ngx_http_s3_gateway_c_module.
# Focus: non-empty static env credentials short-circuit refresh and return 200,
# even when refresh-related env vars are set to failing values.

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
$ENV{AWS_ACCESS_KEY_ID} = 'STATICAK';
$ENV{AWS_SECRET_ACCESS_KEY} = 'STATICSK';
$ENV{AWS_SESSION_TOKEN} = 'STATICTOKEN';
$ENV{AWS_WEB_IDENTITY_TOKEN_FILE} = '/definitely/missing/web_identity_token';
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
env AWS_WEB_IDENTITY_TOKEN_FILE;
env AWS_ROLE_ARN;
env AWS_ROLE_SESSION_NAME;
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
            s3_gateway_content fetchCredentials;
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(3);

my $resp = http_get('/fetch');

like($resp, qr/^HTTP\/1\.1 200 /m,
    'fetchCredentials short-circuits with 200 when static env credentials are configured');
like($resp, qr/\r\nContent-Length: 0\r\n/i,
    'short-circuit response keeps empty body');
like($resp, qr/\r\nContent-Type: text\/plain\r\n/i,
    'short-circuit response content-type is text/plain');
