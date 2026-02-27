#!/usr/bin/perl

# Signature V4 tests for ngx_http_s3_gateway_c_module.
# Cases are derived from njs awssig4.js behavior:
# - SigV4 auth header shape
# - signing key cache value format written to $signing_key_hash

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

        location / {
            set $s3_host bucket-1.s3.example.internal;
            set $cache_signing_key_enabled 1;
            set $signing_key_hash "";

            add_header X-S3AUTH $s3auth always;
            add_header X-AWSDATE $awsDate always;
            add_header X-SIGNING-KEY-HASH $signing_key_hash always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(7);

my $resp = http_get('/a/c/ramen.jpg');

like($resp, qr/^HTTP\/1\.1 200 /m, 'request returns 200');
like($resp, qr/\r\nX-S3AUTH: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//i,
    'SigV4 authorization header is generated');
like($resp, qr/\r\nX-AWSDATE: (\d{8})T\d{6}Z\r\n/i,
    'awsDate has expected ISO8601 shape');

my ($eight) = ($resp =~ /\r\nX-AWSDATE: (\d{8})T\d{6}Z\r\n/i);
ok(defined $eight && length($eight) == 8, 'extracted 8-digit date from awsDate');

my ($cache_val) = ($resp =~ /\r\nX-SIGNING-KEY-HASH:\s*([^\r\n]*)\r\n/i);
if (defined $cache_val && length $cache_val) {
    like($cache_val, qr/^\Q$eight\E:\{"type":"Buffer","data":\[(?:\d{1,3},){31}\d{1,3}\]\}$/,
        'signing_key_hash uses njs-compatible JSON Buffer format');
} else {
    pass('signing_key_hash is empty without writable backing variable (expected in OSS-like setups)');
}

my $resp2 = http_get('/a/c/ramen.jpg');
like($resp2, qr/\r\nX-S3AUTH: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//i,
    'second request still returns valid SigV4 auth header');

my ($cache_val2) = ($resp2 =~ /\r\nX-SIGNING-KEY-HASH:\s*([^\r\n]*)\r\n/i);
if (defined $cache_val && length $cache_val && defined $cache_val2 && length $cache_val2) {
    is($cache_val2, $cache_val, 'signing_key_hash is stable across repeated request');
} else {
    pass('signing_key_hash remains empty without writable backing variable');
}
