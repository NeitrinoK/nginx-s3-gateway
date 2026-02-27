#!/usr/bin/perl

# SigV4 parity tests for ngx_http_s3_gateway_c_module.
# Focus: same forIndexPage/listing interplay in virtual style.

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

        location /dir-forindex {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/";
            set $forIndexPage true;
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }

        location /explicit-index {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/docs/index.html";
            set $forIndexPage false;
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(8);

my $dir = http_get('/dir-forindex');
my $idx = http_get('/explicit-index');

like($dir, qr/^HTTP\/1\.1 200 /m, 'dir-forindex endpoint returns 200');
like($idx, qr/^HTTP\/1\.1 200 /m, 'explicit-index endpoint returns 200');
like($dir, qr/\r\nX-S3URI: \/docs\/\r\n/i,
    'virtual style forIndexPage=true uses directory object URI without bucket prefix');
like($idx, qr/\r\nX-S3URI: \/docs\/index\.html\r\n/i,
    'virtual style explicit index URI remains object path');

my ($dir_auth) = ($dir =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($idx_auth) = ($idx =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
ok(defined $dir_auth && $dir_auth =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
   'forIndexPage request produced SigV4 auth header');
ok(defined $idx_auth && $idx_auth =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
   'explicit index request produced SigV4 auth header');
isnt($dir_auth, $idx_auth,
     'virtual-style directory canonical URI and explicit index URI produce different signatures');
unlike($dir, qr/\?delimiter=%2F&prefix=/i,
       'forIndexPage=true suppresses listing query generation in virtual style too');
