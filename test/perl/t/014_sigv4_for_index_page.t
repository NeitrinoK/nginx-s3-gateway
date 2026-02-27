#!/usr/bin/perl

# SigV4 tests for ngx_http_s3_gateway_c_module.
# Focus: forIndexPage=true + directory path signs same target as explicit index.html.

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
$ENV{ALLOW_DIRECTORY_LIST} = 'true';
$ENV{PROVIDE_INDEX_PAGE} = 'true';
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

        location /dir-sign {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/";
            set $forIndexPage true;
            add_header X-S3AUTH $s3auth always;
            add_header X-AWSDATE $awsDate always;
            return 200 "ok";
        }

        location /file-sign {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/index.html";
            set $forIndexPage false;
            add_header X-S3AUTH $s3auth always;
            add_header X-AWSDATE $awsDate always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(7);

my $dir_resp = http_get('/dir-sign');
my $file_resp = http_get('/file-sign');
my $dir_resp2 = http_get('/dir-sign');

like($dir_resp, qr/^HTTP\/1\.1 200 /m, 'dir-sign endpoint returns 200');
like($file_resp, qr/^HTTP\/1\.1 200 /m, 'file-sign endpoint returns 200');

my ($dir_auth) = ($dir_resp =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($file_auth) = ($file_resp =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
ok(defined $dir_auth && $dir_auth =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
    'dir-sign produced non-empty SigV4 auth header');
ok(defined $file_auth && $file_auth =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
    'file-sign produced non-empty SigV4 auth header');
is($dir_auth, $file_auth,
    'forIndexPage=true + directory path signs the same SigV4 target as explicit index.html path');

my ($dir_date) = ($dir_resp =~ /\r\nX-AWSDATE:\s*([^\r\n]+)\r\n/i);
my ($file_date) = ($file_resp =~ /\r\nX-AWSDATE:\s*([^\r\n]+)\r\n/i);
is($dir_date, $file_date, 'awsDate is identical for both requests in this module lifecycle');

my ($dir_auth2) = ($dir_resp2 =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
is($dir_auth2, $dir_auth, 'forIndexPage=true signature is stable across repeated directory requests');
