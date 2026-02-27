#!/usr/bin/perl

# SigV4 cache behavior tests for ngx_http_s3_gateway_c_module.
# Focus: when signing-key cache is disabled, existing $signing_key_hash is not rewritten.

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
$ENV{AWS_ACCESS_KEY_ID} = 'AKIDEXAMPLE';
$ENV{AWS_SECRET_ACCESS_KEY} = 'SECRETEXAMPLE';
delete $ENV{AWS_SESSION_TOKEN};

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

        location /cache-off {
            set $s3_host bucket-1.s3.example.internal;
            set $cache_signing_key_enabled 0;
            set $signing_key_hash SENTINEL_HASH_VALUE;
            add_header X-S3AUTH $s3auth always;
            add_header X-SIGNING-KEY-HASH $signing_key_hash always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(5);

my $resp1 = http_get('/cache-off');
my $resp2 = http_get('/cache-off');

like($resp1, qr/^HTTP\/1\.1 200 /m, 'first request returns 200');
like($resp1, qr/\r\nX-S3AUTH: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//i,
    'first request generates SigV4 auth');
like($resp1, qr/\r\nX-SIGNING-KEY-HASH: SENTINEL_HASH_VALUE\r\n/i,
    'first request keeps preseeded signing_key_hash when cache is disabled');
like($resp2, qr/^HTTP\/1\.1 200 /m, 'second request returns 200');
like($resp2, qr/\r\nX-SIGNING-KEY-HASH: SENTINEL_HASH_VALUE\r\n/i,
    'second request still keeps preseeded signing_key_hash');

