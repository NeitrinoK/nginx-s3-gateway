#!/usr/bin/perl

# Header filter parity tests for ngx_http_s3_gateway_c_module.
# Focus: in njs, an empty token in HEADER_PREFIXES_TO_STRIP (for example via ";;")
# matches any header because String#indexOf('', 0) == 0.

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
$ENV{HEADER_PREFIXES_TO_STRIP} = 'x-custom-;;';
$ENV{AWS_ACCESS_KEY_ID} = 'AKIDEXAMPLE';
$ENV{AWS_SECRET_ACCESS_KEY} = 'SECRETEXAMPLE';

my $module = $ENV{S3GW_MODULE_SO}
    || "$FindBin::Bin/../../../../nginx/objs/ngx_http_s3_gateway_c_module.so";

my $t = Test::Nginx->new()->has(qw/http proxy/);

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
env HEADER_PREFIXES_TO_STRIP;

events {}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /headers {
            proxy_pass http://127.0.0.1:8081/up;
            s3_gateway_header_filter on;
        }
    }

    server {
        listen 127.0.0.1:8081;
        server_name backend;

        location /up {
            add_header X-Amz-Request-Id amz-123 always;
            add_header X-Custom-Secret hidden always;
            add_header X-Keep yes always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(4);

my $resp = http_get('/headers');
like($resp, qr/^HTTP\/1\.1 200 /m, 'headers endpoint returns 200');
unlike($resp, qr/\r\nX-Keep:/i,
    'empty token from ";;" in strip list behaves like wildcard and strips non-target headers');
unlike($resp, qr/\r\nX-Custom-Secret:/i,
    'explicit custom strip prefix also strips matching header');
unlike($resp, qr/\r\nX-Amz-Request-Id:/i,
    'x-amz-* header remains stripped');

