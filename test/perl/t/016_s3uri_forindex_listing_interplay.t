#!/usr/bin/perl

# Variable parity tests for ngx_http_s3_gateway_c_module.
# Focus: ALLOW_DIRECTORY_LIST=true + forIndexPage=true should disable listing query
# generation and keep object-style URI unless PROVIDE_INDEX_PAGE is also enabled.

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

        location /for-index {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/";
            set $forIndexPage true;
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }

        location /for-list {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/";
            set $forIndexPage false;
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(7);

my $for_index = http_get('/for-index');
my $for_list = http_get('/for-list');

like($for_index, qr/^HTTP\/1\.1 200 /m, 'for-index endpoint returns 200');
like($for_list, qr/^HTTP\/1\.1 200 /m, 'for-list endpoint returns 200');

like($for_index, qr/\r\nX-S3URI: \/bucket-1\/docs\/\r\n/i,
    'forIndexPage=true disables listing query generation and keeps object URI');
like($for_list, qr/\r\nX-S3URI: \/bucket-1\?delimiter=%2F&prefix=docs%2F\r\n/i,
    'forIndexPage=false keeps directory listing query generation');

my ($auth_index) = ($for_index =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($auth_list) = ($for_list =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
ok(defined $auth_index && $auth_index =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
    'for-index request produced a valid SigV4 auth header');
ok(defined $auth_list && $auth_list =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
    'for-list request produced a valid SigV4 auth header');
isnt($auth_index, $auth_list, 'different canonical targets produce different signatures');

