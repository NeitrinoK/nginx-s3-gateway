#!/usr/bin/perl

# SigV4 tests for ngx_http_s3_gateway_c_module.
# Focus: root directory listing canonicalization differs between GET and HEAD
# in virtual style as well.

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

        location /root {
            set $s3_host bucket-1.s3.example.internal;
            set $uri_path "/";
            add_header X-S3URI $s3uri always;
            add_header X-S3AUTH $s3auth always;
            return 200 "ok";
        }
    }
}
EOF_CONF

$conf =~ s/\$module/$module/g;$t->write_file_expand('nginx.conf', $conf);

$t->try_run('no Test::Nginx runtime')->plan(6);

my $get_resp = http_get('/root');
my $head_resp = http_head('/root');

like($get_resp, qr/^HTTP\/1\.1 200 /m, 'GET /root returns 200');
like($head_resp, qr/^HTTP\/1\.1 200 /m, 'HEAD /root returns 200');
like($get_resp, qr/\r\nX-S3URI: \?delimiter=%2F\r\n/i,
    'GET /root uses delimiter query for virtual-style directory listing');
like($head_resp, qr/\r\nX-S3URI: \/\r\n/i,
    'HEAD /root uses object-style root path for virtual style');

my ($get_auth) = ($get_resp =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
my ($head_auth) = ($head_resp =~ /\r\nX-S3AUTH:\s*([^\r\n]+)\r\n/i);
ok(defined $get_auth && defined $head_auth, 'both methods produce auth headers');
isnt($get_auth, $head_auth,
     'GET and HEAD root requests produce different SigV4 signatures in virtual style');
