#!/usr/bin/perl

# SigV4 tests for ngx_http_s3_gateway_c_module.
# Focus: canonical host is part of signature, so changing $s3_host changes auth.

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
$ENV{AWS_ACCESS_KEY_ID} = 'AKIDEXAMPLE';
$ENV{AWS_SECRET_ACCESS_KEY} = 'SECRETEXAMPLE';
delete $ENV{AWS_SESSION_TOKEN};
delete $ENV{S3_SERVICE};

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
env S3_SERVICE;
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

        location /host-a {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/a/c/ramen.jpg";
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }

        location /host-b {
            set $s3_host bucket-1.alt-s3.example.internal;
            set $uri_path "/a/c/ramen.jpg";
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(5);

my $a = http_get('/host-a');
my $b = http_get('/host-b');

like($a, qr/^HTTP\/1\.1 200 /m, 'host-a endpoint returns 200');
like($b, qr/^HTTP\/1\.1 200 /m, 'host-b endpoint returns 200');

my ($a_auth) = ($a =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($b_auth) = ($b =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
ok(defined $a_auth && $a_auth =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
   'host-a produced SigV4 auth header');
ok(defined $b_auth && $b_auth =~ /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//,
   'host-b produced SigV4 auth header');
isnt($a_auth, $b_auth,
     'changing canonical host changes SigV4 signature');
