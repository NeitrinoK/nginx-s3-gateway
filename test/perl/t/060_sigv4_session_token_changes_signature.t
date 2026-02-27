#!/usr/bin/perl

# SigV4 credential tests for ngx_http_s3_gateway_c_module.
# Focus: session token presence changes SignedHeaders and resulting signature.

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

        location /with-token {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/obj.txt";
            set $cache_instance_credentials_enabled 1;
            set $instance_credential_json '{"accessKeyId":"K","secretAccessKey":"S","sessionToken":"TOK","expiration":"2030-01-01T00:00:00Z"}';
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }

        location /without-token {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/obj.txt";
            set $cache_instance_credentials_enabled 1;
            set $instance_credential_json '{"accessKeyId":"K","secretAccessKey":"S","expiration":"2030-01-01T00:00:00Z"}';
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(6);

my $with = http_get('/with-token');
my $without = http_get('/without-token');

like($with, qr/^HTTP\/1\.1 200 /m, 'with-token endpoint returns 200');
like($without, qr/^HTTP\/1\.1 200 /m, 'without-token endpoint returns 200');

my ($with_auth) = ($with =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($without_auth) = ($without =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);

like($with_auth, qr/SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature=/,
    'with-token signature includes x-amz-security-token in SignedHeaders');
like($without_auth, qr/SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=/,
    'without-token signature omits x-amz-security-token from SignedHeaders');
like($with_auth, qr/^AWS4-HMAC-SHA256 Credential=K\//,
    'with-token auth is valid SigV4 header');
isnt($with_auth, $without_auth,
     'SigV4 signature changes when session token is present');
