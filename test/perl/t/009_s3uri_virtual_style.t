#!/usr/bin/perl

# Variable tests for ngx_http_s3_gateway_c_module.
# Focus: $s3uri behavior with S3_STYLE=virtual.

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
$ENV{S3_STYLE} = 'virtual';
$ENV{ALLOW_DIRECTORY_LIST} = 'true';
$ENV{PROVIDE_INDEX_PAGE} = 'false';
$ENV{APPEND_SLASH_FOR_POSSIBLE_DIRECTORY} = 'false';
$ENV{FOUR_O_FOUR_ON_EMPTY_BUCKET} = 'false';
$ENV{AWS_ACCESS_KEY_ID} = 'AKIDEXAMPLE';
$ENV{AWS_SECRET_ACCESS_KEY} = 'SECRETEXAMPLE';

my $module = $ENV{S3GW_MODULE_SO}
    || "$FindBin::Bin/../../../../nginx/objs/ngx_http_s3_gateway_c_module.so";

my $t = Test::Nginx->new()->has(qw/http/);

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
            add_header X-S3URI $s3uri always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(6);

my $file = http_get('/a/c/ramen.jpg');
like($file, qr/^HTTP\/1\.1 200 /m, 'file request returns 200');
like($file, qr/\r\nX-S3URI: \/a\/c\/ramen\.jpg\r\n/i,
    'virtual style file URI does not include bucket prefix');

my $dir = http_get('/b/c/');
like($dir, qr/^HTTP\/1\.1 200 /m, 'directory request returns 200');
like($dir, qr/\r\nX-S3URI: \?delimiter=%2F&prefix=b%2Fc%2F\r\n/i,
    'virtual style directory listing query has no path-style bucket prefix');

my $root = http_get('/');
like($root, qr/^HTTP\/1\.1 200 /m, 'root request returns 200');
like($root, qr/\r\nX-S3URI: \?delimiter=%2F\r\n/i,
    'virtual style root listing query is delimiter-only');
