#!/usr/bin/perl

# SigV4/S3 URI tests for ngx_http_s3_gateway_c_module.
# Focus: directory listing query parameters are generated only for GET requests.

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

        location /dir {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/";
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(7);

my $get_resp = http_get('/dir');
my $post_resp = http(<<'EOF_REQ');
POST /dir HTTP/1.0
Host: localhost
Content-Length: 0

EOF_REQ

like($get_resp, qr/^HTTP\/1\.1 200 /m, 'GET directory endpoint returns 200');
like($post_resp, qr/^HTTP\/1\.1 200 /m, 'POST directory endpoint returns 200');
like($get_resp, qr/\r\nX-S3URI: \/bucket-1\?delimiter=%2F&prefix=docs%2F\r\n/i,
    'GET generates listing query parameters for directory path');
like($post_resp, qr/\r\nX-S3URI: \/bucket-1\/docs\/\r\n/i,
    'non-GET request signs object-style directory path without listing query');

my ($get_auth) = ($get_resp =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($post_auth) = ($post_resp =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
like($get_auth, qr/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
    'GET returns valid SigV4 auth header');
like($post_auth, qr/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
    'POST returns valid SigV4 auth header');
isnt($get_auth, $post_auth,
    'GET and POST signatures differ because canonical URI/query differ');

