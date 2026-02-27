#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

export S3GW_MODULE_SO="${S3GW_MODULE_SO:-$ROOT_DIR/nginx/objs/ngx_http_s3_gateway_c_module.so}"
export TEST_NGINX_BINARY="${TEST_NGINX_BINARY:-$ROOT_DIR/nginx/objs/nginx}"
if [ -z "${TEST_NGINX_GLOBALS_HTTP:-}" ]; then
  export TEST_NGINX_GLOBALS_HTTP='map $request_uri $instance_credential_json { default ""; } map $request_uri $signing_key_hash { default ""; }'
fi

if [ -d "$ROOT_DIR/nginx-tests/lib" ]; then
  export PERL5LIB="$ROOT_DIR/nginx-tests/lib:${PERL5LIB:-}"
fi

prove -r "$SCRIPT_DIR/t"
