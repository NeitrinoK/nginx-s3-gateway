#!/usr/bin/perl

# SigV2/S3 URI tests for ngx_http_s3_gateway_c_module.
# Focus: in virtual style, $s3uri omits bucket while SigV2 canonical URI still uses bucket.

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

        location /file {
            set $uri_path "/a/c/ramen.jpg";
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }

        location /dir {
            set $uri_path "/docs/";
            set $forIndexPage false;
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }

        location /root {
            set $uri_path "/";
            set $forIndexPage false;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(8);

my $file = http_get('/file');
my $dir = http_get('/dir');
my $root = http_get('/root');

like($file, qr/^HTTP\/1\.1 200 /m, 'file endpoint returns 200');
like($dir, qr/^HTTP\/1\.1 200 /m, 'dir endpoint returns 200');
like($root, qr/^HTTP\/1\.1 200 /m, 'root endpoint returns 200');
like($file, qr/\r\nX-S3URI: \/a\/c\/ramen\.jpg\r\n/i,
    'virtual style file $s3uri has no bucket prefix');
like($dir, qr/\r\nX-S3URI: \?delimiter=%2F&prefix=docs%2F\r\n/i,
    'virtual style directory $s3uri has delimiter/prefix query without bucket');

my ($dir_auth) = ($dir =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($root_auth) = ($root =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
like($dir_auth, qr/^AWS AKIDEXAMPLE:/,
    'directory request produced SigV2 auth header');
like($root_auth, qr/^AWS AKIDEXAMPLE:/,
    'root request produced SigV2 auth header');
is($dir_auth, $root_auth,
   'virtual-style directory canonical URI parity matches root (/bucket/) in SigV2');
