#!/usr/bin/perl

# Redirect flow parity tests for ngx_http_s3_gateway_c_module.
# Focus: when both ALLOW_DIRECTORY_LIST and PROVIDE_INDEX_PAGE are true,
# directory listing branch must stay first and Range must not bypass it.

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
$ENV{AWS_SIGS_VERSION} = '2';
$ENV{S3_STYLE} = 'path';
$ENV{ALLOW_DIRECTORY_LIST} = 'true';
$ENV{PROVIDE_INDEX_PAGE} = 'true';
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
            s3_gateway_content redirectToS3;
        }

        location @s3 {
            return 204;
        }

        location @s3_sliced {
            return 206;
        }

        location @s3PreListing {
            return 200 "listing";
        }

        location @error404 {
            return 404;
        }

        location @error405 {
            add_header Allow "GET,HEAD" always;
            return 405;
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(4);

like(http_get('/dir/'), qr/^HTTP\/1\.1 200 /m,
    'directory request still prefers @s3PreListing when index pages are enabled');

like(http_get('/'), qr/^HTTP\/1\.1 200 /m,
    'root request is treated as directory and goes to @s3PreListing');

like(http_get('/file.txt'), qr/^HTTP\/1\.1 204 /m,
    'non-directory path still goes to @s3');

like(http_head('/dir/'), qr/^HTTP\/1\.1 200 /m,
    'HEAD directory request follows the same pre-listing priority branch');
