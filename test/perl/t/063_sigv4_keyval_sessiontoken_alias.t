#!/usr/bin/perl

# SigV4 credential-source tests for ngx_http_s3_gateway_c_module.
# Focus: SessionToken alias in keyval JSON is recognized as a valid session token.

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
            set $cache_instance_credentials_enabled 1;
            set $instance_credential_json '{"AccessKeyId":"UPPERAK","SecretAccessKey":"UPPERSECRET","SessionToken":"SESSION-ALIAS","Expiration":"2030-01-01T00:00:00Z"}';
            add_header X-S3AUTH $s3auth always;
            add_header X-TOKEN "[$awsSessionToken]" always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(4);

my $resp = http_get('/a/c/ramen.jpg');

like($resp, qr/^HTTP\/1\.1 200 /m, 'request returns 200');
like($resp, qr/\r\nX-TOKEN: \[SESSION-ALIAS\]\r\n/i,
    '$awsSessionToken reads SessionToken alias from credentials JSON');
like($resp, qr/\r\nX-S3AUTH: AWS4-HMAC-SHA256 Credential=UPPERAK\//i,
    'SigV4 auth uses AccessKeyId alias with SessionToken alias present');
like($resp, qr/SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token/i,
    'SigV4 signed headers include security token for SessionToken alias');
