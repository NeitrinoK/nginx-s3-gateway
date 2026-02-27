#include <ngx_config.h>
#include <unistd.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include <curl/curl.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** @brief Default object name used as directory index. */
#define NGX_S3GW_INDEX_PAGE "index.html"
/** @brief Default AWS service for signing when S3_SERVICE is not set. */
#define NGX_S3GW_SERVICE_DEFAULT "s3"
/** @brief Refresh credentials slightly before real expiration (milliseconds). */
#define NGX_S3GW_MAX_VALIDITY_OFFSET_MS (270000)
/** @brief Total timeout for metadata/STS curl requests in milliseconds. */
#define NGX_S3GW_CURL_TIMEOUT_MS (1500L)
/** @brief Connect timeout for metadata/STS curl requests in milliseconds. */
#define NGX_S3GW_CURL_CONNECT_TIMEOUT_MS (500L)

/** @brief Literal value that enables AWS Signature V2 flow. */
#define NGX_S3GW_AWS_V2 "2"
/** @brief Path-style addressing mode for S3 URIs. */
#define NGX_S3GW_S3_STYLE_PATH "path"

/** @brief ECS metadata base URL used with relative credentials path. */
#define NGX_S3GW_ECS_CREDENTIAL_BASE_URI "http://169.254.170.2"
/** @brief EC2 IMDSv2 token endpoint. */
#define NGX_S3GW_EC2_IMDS_TOKEN_ENDPOINT "http://169.254.169.254/latest/api/token"
/** @brief EC2 IMDS endpoint returning IAM role names and credentials. */
#define NGX_S3GW_EC2_IMDS_SECURITY_CREDENTIALS_ENDPOINT "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
/** @brief EKS Pod Identity Agent credentials endpoint. */
#define NGX_S3GW_EKS_POD_IDENTITY_AGENT_CREDENTIALS_ENDPOINT "http://169.254.170.23/v1/credentials"

/**
 * @brief Logical content handlers exposed by s3_gateway_content directive.
 */
typedef enum {
    NGX_S3GW_CONTENT_NONE = 0,
    NGX_S3GW_CONTENT_REDIRECT_TO_S3,
    NGX_S3GW_CONTENT_TRAILSLASH_CONTROL,
    NGX_S3GW_CONTENT_LOAD_CONTENT,
    NGX_S3GW_CONTENT_FETCH_CREDENTIALS
} ngx_s3gw_content_mode_e;

/**
 * @brief Cached environment/config values resolved once during module init.
 */
typedef struct {
    ngx_flag_t inited;

    ngx_flag_t debug;
    ngx_flag_t allow_listing;
    ngx_flag_t provide_index_page;
    ngx_flag_t append_slash;
    ngx_flag_t four_404_on_empty_bucket;

    ngx_str_t s3_bucket_name;
    ngx_str_t s3_server;
    ngx_str_t s3_server_proto;
    ngx_str_t s3_server_port;
    ngx_str_t s3_region;
    ngx_str_t aws_sigs_version;
    ngx_str_t s3_style;
    ngx_str_t s3_service;

    ngx_array_t *header_prefixes_to_strip; /* ngx_str_t */
    ngx_array_t *header_prefixes_allowed;  /* ngx_str_t */
} ngx_s3gw_env_t;

/**
 * @brief Per-location toggles for content mode and output filters.
 */
typedef struct {
    ngx_flag_t enable_header_filter;
    ngx_flag_t enable_body_filter;
    ngx_uint_t content_mode;
} ngx_s3gw_loc_conf_t;

/**
 * @brief Request context for body filter state across response chunks.
 */
typedef struct {
    ngx_flag_t initialized;
    ngx_flag_t index_is_empty;
    ngx_flag_t now_initialized;
    time_t now_sec;
    ngx_str_t now_http_date;
    ngx_str_t now_eight_date;
    ngx_str_t now_amz_date;
} ngx_s3gw_body_ctx_t;

/**
 * @brief Request context used by loadContent subrequest callback.
 */
typedef struct {
    ngx_str_t uri;
} ngx_s3gw_load_content_ctx_t;

/**
 * @brief In-memory AWS credentials representation.
 */
typedef struct {
    ngx_str_t access_key_id;
    ngx_str_t secret_access_key;
    ngx_str_t session_token;
    ngx_str_t expiration;

    ngx_flag_t has_session_token;
    ngx_flag_t has_expiration;
    ngx_flag_t present;
} ngx_s3gw_credentials_t;

/**
 * @brief Minimal HTTP response container for libcurl calls.
 */
typedef struct {
    long status;
    u_char *body;
    size_t body_len;
} ngx_s3gw_http_response_t;

/**
 * @brief Dynamic write buffer used by libcurl callback.
 */
typedef struct {
    u_char *data;
    size_t len;
} ngx_s3gw_curl_buffer_t;

static ngx_s3gw_env_t ngx_s3gw_env;

static time_t ngx_s3gw_now_sec;
static ngx_str_t ngx_s3gw_now_http_date;
static ngx_str_t ngx_s3gw_now_eight_date;
static ngx_str_t ngx_s3gw_now_amz_date;

static ngx_http_output_header_filter_pt ngx_s3gw_next_header_filter;
static ngx_http_output_body_filter_pt ngx_s3gw_next_body_filter;

static ngx_str_t ngx_s3gw_named_error405 = ngx_string("@error405");
static ngx_str_t ngx_s3gw_named_error404 = ngx_string("@error404");
static ngx_str_t ngx_s3gw_named_error500 = ngx_string("@error500");
static ngx_str_t ngx_s3gw_named_s3 = ngx_string("@s3");
static ngx_str_t ngx_s3gw_named_s3_sliced = ngx_string("@s3_sliced");
static ngx_str_t ngx_s3gw_named_s3_pre_listing = ngx_string("@s3PreListing");
static ngx_str_t ngx_s3gw_named_s3_directory = ngx_string("@s3Directory");
static ngx_str_t ngx_s3gw_named_trailslash = ngx_string("@trailslash");

static ngx_str_t ngx_s3gw_var_uri_path = ngx_string("uri_path");
static ngx_str_t ngx_s3gw_var_for_index_page = ngx_string("forIndexPage");
static ngx_str_t ngx_s3gw_var_for_index_page_lc = ngx_string("forindexpage");
static ngx_str_t ngx_s3gw_var_index_is_empty = ngx_string("indexIsEmpty");
static ngx_str_t ngx_s3gw_var_index_is_empty_lc = ngx_string("indexisempty");
static ngx_str_t ngx_s3gw_var_s3_host = ngx_string("s3_host");
static ngx_str_t ngx_s3gw_var_cache_signing_key_enabled = ngx_string("cache_signing_key_enabled");
static ngx_str_t ngx_s3gw_var_cache_instance_credentials_enabled = ngx_string("cache_instance_credentials_enabled");
static ngx_str_t ngx_s3gw_var_signing_key_hash = ngx_string("signing_key_hash");
static ngx_str_t ngx_s3gw_var_instance_credential_json = ngx_string("instance_credential_json");
static ngx_str_t ngx_s3gw_var_request_body = ngx_string("request_body");

static ngx_str_t ngx_s3gw_var_s3auth = ngx_string("s3auth");
static ngx_str_t ngx_s3gw_var_s3uri = ngx_string("s3uri");
static ngx_str_t ngx_s3gw_var_http_date = ngx_string("httpDate");
static ngx_str_t ngx_s3gw_var_aws_date = ngx_string("awsDate");
static ngx_str_t ngx_s3gw_var_aws_payload_hash = ngx_string("awsPayloadHash");
static ngx_str_t ngx_s3gw_var_aws_session_token = ngx_string("awsSessionToken");

static ngx_int_t ngx_s3gw_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_s3gw_init(ngx_conf_t *cf);
static void ngx_s3gw_exit_process(ngx_cycle_t *cycle);

static void *ngx_s3gw_create_loc_conf(ngx_conf_t *cf);
static char *ngx_s3gw_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_s3gw_set_content_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_s3gw_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_s3gw_redirect_to_s3(ngx_http_request_t *r);
static ngx_int_t ngx_s3gw_trailslash_control(ngx_http_request_t *r);
static ngx_int_t ngx_s3gw_load_content(ngx_http_request_t *r);
static ngx_int_t ngx_s3gw_load_content_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_s3gw_fetch_credentials_handler(ngx_http_request_t *r);

static ngx_int_t ngx_s3gw_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_s3gw_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_int_t ngx_s3gw_var_s3auth_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_s3gw_var_s3uri_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_s3gw_var_http_date_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_s3gw_var_aws_date_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_s3gw_var_aws_payload_hash_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_s3gw_var_aws_session_token_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_s3gw_init_env(ngx_conf_t *cf);
static ngx_int_t ngx_s3gw_init_now_strings(ngx_conf_t *cf);
static ngx_int_t ngx_s3gw_ensure_now(ngx_http_request_t *r);

static ngx_flag_t ngx_s3gw_parse_boolean_str(const ngx_str_t *value);
static ngx_flag_t ngx_s3gw_parse_boolean_cstr(const char *value);

static ngx_int_t ngx_s3gw_parse_semicolon_array(ngx_pool_t *pool, const char *raw, ngx_array_t **out);

static ngx_int_t ngx_s3gw_get_variable(ngx_http_request_t *r, const ngx_str_t *name, ngx_str_t *out);
static ngx_int_t ngx_s3gw_get_variable_dual(ngx_http_request_t *r, const ngx_str_t *a, const ngx_str_t *b, ngx_str_t *out);
static ngx_int_t ngx_s3gw_set_variable_by_index(ngx_http_request_t *r, ngx_int_t index, const ngx_str_t *value);
static ngx_int_t ngx_s3gw_get_uri_path(ngx_http_request_t *r, ngx_str_t *out);
static ngx_flag_t ngx_s3gw_get_for_index_page(ngx_http_request_t *r);
static ngx_flag_t ngx_s3gw_get_index_is_empty_initial(ngx_http_request_t *r);

static ngx_flag_t ngx_s3gw_is_directory(const ngx_str_t *path);
static ngx_flag_t ngx_s3gw_ends_with(const ngx_str_t *value, const char *suffix);

static ngx_int_t ngx_s3gw_percent_decode(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst);
static ngx_int_t ngx_s3gw_encode_uri_component(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst);
static ngx_int_t ngx_s3gw_escape_uri_path(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst);

static ngx_int_t ngx_s3gw_build_s3_base_uri(ngx_pool_t *pool, ngx_str_t *out);
static ngx_int_t ngx_s3gw_build_s3_dir_query_params(ngx_http_request_t *r, const ngx_str_t *uri_path, ngx_str_t *out);
static ngx_int_t ngx_s3gw_build_s3_uri(ngx_http_request_t *r, ngx_str_t *out);

static ngx_flag_t ngx_s3gw_header_contains(const ngx_str_t *header_lc, const ngx_str_t *needle);
static ngx_flag_t ngx_s3gw_header_should_be_allowed(const ngx_str_t *header_lc);
static ngx_flag_t ngx_s3gw_header_should_be_stripped(const ngx_str_t *header_lc);

static ngx_int_t ngx_s3gw_read_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds);
static ngx_int_t ngx_s3gw_write_credentials(ngx_http_request_t *r, const ngx_s3gw_credentials_t *creds);
static ngx_int_t ngx_s3gw_fetch_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds);

static ngx_int_t ngx_s3gw_fetch_ecs_role_credentials(ngx_http_request_t *r, const ngx_str_t *uri, ngx_s3gw_credentials_t *creds);
static ngx_int_t ngx_s3gw_fetch_ec2_role_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds);
static ngx_int_t ngx_s3gw_fetch_web_identity_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds);
static ngx_int_t ngx_s3gw_fetch_eks_pod_identity_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds);

static ngx_int_t ngx_s3gw_http_request(ngx_pool_t *pool, const ngx_str_t *url, const char *method, struct curl_slist *headers, ngx_s3gw_http_response_t *resp);
static size_t ngx_s3gw_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp);
static ngx_int_t ngx_s3gw_curl_slist_append_safe(struct curl_slist **list, const char *line);

static ngx_int_t ngx_s3gw_json_get_string(ngx_pool_t *pool, const ngx_str_t *json, const char *key, ngx_str_t *out);
static ngx_int_t ngx_s3gw_build_credentials_from_json(ngx_pool_t *pool, const ngx_str_t *json, ngx_s3gw_credentials_t *creds);
static ngx_int_t ngx_s3gw_parse_expiration_ms(const ngx_str_t *expiration, uint64_t *out_ms);
static ngx_int_t ngx_s3gw_read_file(ngx_pool_t *pool, const ngx_str_t *path, ngx_str_t *out);
static ngx_int_t ngx_s3gw_write_file(const ngx_str_t *path, const ngx_str_t *content);
static ngx_int_t ngx_s3gw_credentials_temp_file(ngx_pool_t *pool, ngx_str_t *path);
static ngx_int_t ngx_s3gw_trim_whitespace(ngx_str_t *value);

static ngx_int_t ngx_s3gw_signature_v2(ngx_http_request_t *r, const ngx_str_t *uri, const ngx_str_t *http_date, const ngx_s3gw_credentials_t *creds, ngx_str_t *out);
static ngx_int_t ngx_s3gw_signature_v4(ngx_http_request_t *r, const ngx_str_t *uri, const ngx_str_t *query_params, const ngx_str_t *host, const ngx_s3gw_credentials_t *creds, ngx_str_t *out);
static ngx_int_t ngx_s3gw_payload_hash(ngx_http_request_t *r, ngx_str_t *out);

static ngx_int_t ngx_s3gw_hmac_sha1_base64(ngx_pool_t *pool, const ngx_str_t *key, const ngx_str_t *msg, ngx_str_t *out);
static ngx_int_t ngx_s3gw_hmac_sha256_raw(const ngx_str_t *key, const ngx_str_t *msg, u_char out[SHA256_DIGEST_LENGTH]);
static ngx_int_t ngx_s3gw_hmac_sha256_hex(ngx_pool_t *pool, const ngx_str_t *key, const ngx_str_t *msg, ngx_str_t *out);
static ngx_int_t ngx_s3gw_sha256_hex(ngx_pool_t *pool, const ngx_str_t *msg, ngx_str_t *out);

static ngx_int_t ngx_s3gw_set_var_value(ngx_pool_t *pool, ngx_http_variable_value_t *v, const ngx_str_t *value);
static ngx_int_t ngx_s3gw_send_empty_status(ngx_http_request_t *r, ngx_uint_t status);

static ngx_int_t ngx_s3gw_var_index_instance_credential_json = NGX_CONF_UNSET;
static ngx_int_t ngx_s3gw_var_index_signing_key_hash = NGX_CONF_UNSET;

static ngx_command_t ngx_s3gw_commands[] = {
    {
        ngx_string("s3_gateway_content"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_s3gw_set_content_directive,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("s3_gateway_header_filter"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_s3gw_loc_conf_t, enable_header_filter),
        NULL
    },
    {
        ngx_string("s3_gateway_body_filter"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_s3gw_loc_conf_t, enable_body_filter),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_s3gw_module_ctx = {
    ngx_s3gw_add_variables,  /* preconfiguration */
    ngx_s3gw_init,           /* postconfiguration */

    NULL,                    /* create main conf */
    NULL,                    /* init main conf */

    NULL,                    /* create srv conf */
    NULL,                    /* merge srv conf */

    ngx_s3gw_create_loc_conf,
    ngx_s3gw_merge_loc_conf
};

ngx_module_t ngx_http_s3_gateway_c_module = {
    NGX_MODULE_V1,
    &ngx_s3gw_module_ctx,
    ngx_s3gw_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_s3gw_exit_process,
    NULL,
    NGX_MODULE_V1_PADDING
};

/**
 * @brief debug log.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param fmt printf-style format string for debug logging.
 * @param ... Additional arguments consumed by the format string.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_debug_log(ngx_http_request_t *r, const char *fmt, ...)
{
    va_list args;
    u_char buf[512];
    u_char *p;

    if (!ngx_s3gw_env.debug) {
        return NGX_OK;
    }

    va_start(args, fmt);
    p = ngx_vslprintf(buf, buf + sizeof(buf) - 1, fmt, args);
    va_end(args);
    *p = '\0';

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "s3gw: %s", buf);
    return NGX_OK;
}

/**
 * @brief add single variable.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @param name Variable or field name used by the helper.
 * @param handler Nginx variable handler callback to register.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_add_single_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_http_get_variable_pt handler)
{
    ngx_http_variable_t *var;

    var = ngx_http_add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = handler;
    return NGX_OK;
}

/**
 * @brief add variables.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_add_variables(ngx_conf_t *cf)
{
    if (ngx_s3gw_add_single_variable(cf, &ngx_s3gw_var_s3auth, ngx_s3gw_var_s3auth_handler) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_add_single_variable(cf, &ngx_s3gw_var_s3uri, ngx_s3gw_var_s3uri_handler) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_add_single_variable(cf, &ngx_s3gw_var_http_date, ngx_s3gw_var_http_date_handler) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_add_single_variable(cf, &ngx_s3gw_var_aws_date, ngx_s3gw_var_aws_date_handler) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_add_single_variable(cf, &ngx_s3gw_var_aws_payload_hash, ngx_s3gw_var_aws_payload_hash_handler) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_add_single_variable(cf, &ngx_s3gw_var_aws_session_token, ngx_s3gw_var_aws_session_token_handler) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief init.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_init(ngx_conf_t *cf)
{
    if (ngx_s3gw_var_index_instance_credential_json == NGX_CONF_UNSET) {
        ngx_s3gw_var_index_instance_credential_json =
            ngx_http_get_variable_index(cf, &ngx_s3gw_var_instance_credential_json);
        if (ngx_s3gw_var_index_instance_credential_json == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (ngx_s3gw_var_index_signing_key_hash == NGX_CONF_UNSET) {
        ngx_s3gw_var_index_signing_key_hash =
            ngx_http_get_variable_index(cf, &ngx_s3gw_var_signing_key_hash);
        if (ngx_s3gw_var_index_signing_key_hash == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (ngx_s3gw_init_env(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_init_now_strings(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "s3gw: failed to initialize libcurl");
        return NGX_ERROR;
    }

    ngx_s3gw_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_s3gw_header_filter;

    ngx_s3gw_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_s3gw_body_filter;

    return NGX_OK;
}

/**
 * @brief exit process.
 * @details Releases process-level resources allocated by third-party libraries.
 * @param cycle Nginx cycle object for the exiting worker process.
 */
static void
ngx_s3gw_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;
    curl_global_cleanup();
}

/**
 * @brief create loc conf.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @return Pointer result, or NULL on failure.
 */
static void *
ngx_s3gw_create_loc_conf(ngx_conf_t *cf)
{
    ngx_s3gw_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_s3gw_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable_header_filter = NGX_CONF_UNSET;
    conf->enable_body_filter = NGX_CONF_UNSET;
    conf->content_mode = NGX_CONF_UNSET_UINT;

    return conf;
}

/**
 * @brief merge loc conf.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @param parent Parent location configuration inherited by child block.
 * @param child Child location configuration to merge with parent values.
 * @return NGINX configuration parsing result string (for example NGX_CONF_OK/NGX_CONF_ERROR).
 */
static char *
ngx_s3gw_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_s3gw_loc_conf_t *prev = parent;
    ngx_s3gw_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable_header_filter, prev->enable_header_filter, 0);
    ngx_conf_merge_value(conf->enable_body_filter, prev->enable_body_filter, 0);
    ngx_conf_merge_uint_value(conf->content_mode, prev->content_mode, NGX_S3GW_CONTENT_NONE);

    return NGX_CONF_OK;
}

/**
 * @brief set content directive.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @param cmd Nginx directive metadata for the parser callback.
 * @param conf Directive target configuration structure.
 * @return NGINX configuration parsing result string (for example NGX_CONF_OK/NGX_CONF_ERROR).
 */
static char *
ngx_s3gw_set_content_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_s3gw_loc_conf_t *slcf = conf;
    ngx_str_t *value;
    ngx_http_core_loc_conf_t *clcf;

    value = cf->args->elts;

    if (value[1].len == sizeof("redirectToS3") - 1
        && ngx_strncmp(value[1].data, "redirectToS3", value[1].len) == 0)
    {
        slcf->content_mode = NGX_S3GW_CONTENT_REDIRECT_TO_S3;

    } else if (value[1].len == sizeof("trailslashControl") - 1
               && ngx_strncmp(value[1].data, "trailslashControl", value[1].len) == 0)
    {
        slcf->content_mode = NGX_S3GW_CONTENT_TRAILSLASH_CONTROL;

    } else if (value[1].len == sizeof("loadContent") - 1
               && ngx_strncmp(value[1].data, "loadContent", value[1].len) == 0)
    {
        slcf->content_mode = NGX_S3GW_CONTENT_LOAD_CONTENT;

    } else if (value[1].len == sizeof("fetchCredentials") - 1
               && ngx_strncmp(value[1].data, "fetchCredentials", value[1].len) == 0)
    {
        slcf->content_mode = NGX_S3GW_CONTENT_FETCH_CREDENTIALS;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "s3_gateway_content: unsupported mode \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_s3gw_content_handler;

    return NGX_CONF_OK;
}

/**
 * @brief content handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_content_handler(ngx_http_request_t *r)
{
    ngx_s3gw_loc_conf_t *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_s3_gateway_c_module);

    switch (lcf->content_mode) {
        case NGX_S3GW_CONTENT_REDIRECT_TO_S3:
            return ngx_s3gw_redirect_to_s3(r);
        case NGX_S3GW_CONTENT_TRAILSLASH_CONTROL:
            return ngx_s3gw_trailslash_control(r);
        case NGX_S3GW_CONTENT_LOAD_CONTENT:
            return ngx_s3gw_load_content(r);
        case NGX_S3GW_CONTENT_FETCH_CREDENTIALS:
            return ngx_s3gw_fetch_credentials_handler(r);
        default:
            return NGX_DECLINED;
    }
}

/**
 * @brief send empty status.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param status HTTP status code to return.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_send_empty_status(ngx_http_request_t *r, ngx_uint_t status)
{
    ngx_int_t rc;

    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_str_set(&r->headers_out.content_type, "text/plain");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/**
 * @brief redirect to s3.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_redirect_to_s3(ngx_http_request_t *r)
{
    ngx_str_t uri_path;

    if (!(r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD)) {
        ngx_s3gw_debug_log(r, "Invalid method requested: %V", &r->method_name);
        return ngx_http_named_location(r, &ngx_s3gw_named_error405);
    }

    if (ngx_s3gw_get_uri_path(r, &uri_path) != NGX_OK) {
        return ngx_http_named_location(r, &ngx_s3gw_named_error404);
    }

    if (ngx_s3gw_env.allow_listing && ngx_s3gw_is_directory(&uri_path)) {
        return ngx_http_named_location(r, &ngx_s3gw_named_s3_pre_listing);
    }

    if (ngx_s3gw_env.provide_index_page) {
        return ngx_http_named_location(r, &ngx_s3gw_named_s3);
    }

    if (!ngx_s3gw_env.allow_listing && !ngx_s3gw_env.provide_index_page
        && uri_path.len == 1 && uri_path.data[0] == '/')
    {
        return ngx_http_named_location(r, &ngx_s3gw_named_error404);
    }

    if (r->headers_in.range != NULL) {
        return ngx_http_named_location(r, &ngx_s3gw_named_s3_sliced);
    }

    return ngx_http_named_location(r, &ngx_s3gw_named_s3);
}

/**
 * @brief segment has single extension.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param path Filesystem or URI path value being processed.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_segment_has_single_extension(const ngx_str_t *path)
{
    /*
     * njs parity: mirrors /\/[^.\/]+\.[^.]+$/ from trailslashControl().
     * The suffix class [^.]+ intentionally allows '/'. This means a dot in an
     * earlier segment can satisfy the pattern if the remainder has no dots.
     */
    size_t i;

    if (path == NULL || path->len == 0) {
        return 0;
    }

    for (i = 0; i < path->len; i++) {
        size_t j;
        size_t k;

        if (path->data[i] != '/') {
            continue;
        }

        j = i + 1;
        while (j < path->len && path->data[j] != '.' && path->data[j] != '/') {
            j++;
        }

        if (j == i + 1 || j >= path->len || path->data[j] != '.') {
            continue;
        }

        if (j + 1 >= path->len) {
            continue;
        }

        for (k = j + 1; k < path->len; k++) {
            if (path->data[k] == '.') {
                break;
            }
        }

        if (k == path->len) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief trailslash control.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_trailslash_control(ngx_http_request_t *r)
{
    ngx_str_t uri_path;
    ngx_str_t path;
    size_t i;

    if (!ngx_s3gw_env.append_slash) {
        return ngx_http_named_location(r, &ngx_s3gw_named_error404);
    }

    if (ngx_s3gw_get_uri_path(r, &uri_path) != NGX_OK) {
        return ngx_http_named_location(r, &ngx_s3gw_named_error404);
    }

    path = uri_path;
    for (i = 0; i < path.len; i++) {
        if (path.data[i] == '?' || path.data[i] == '#') {
            path.len = i;
            break;
        }
    }

    if (!ngx_s3gw_is_directory(&path) && !ngx_s3gw_segment_has_single_extension(&path)) {
        return ngx_http_named_location(r, &ngx_s3gw_named_trailslash);
    }

    return ngx_http_named_location(r, &ngx_s3gw_named_error404);
}

/**
 * @brief load content.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_load_content(ngx_http_request_t *r)
{
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_s3gw_load_content_ctx_t *ctx;

    if (!ngx_s3gw_env.provide_index_page) {
        return ngx_http_named_location(r, &ngx_s3gw_named_s3_directory);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_s3gw_load_content_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_s3gw_build_s3_uri(r, &ctx->uri) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ps = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ps->handler = ngx_s3gw_load_content_post_subrequest;
    ps->data = ctx;

    /* Emulate njs ngx.fetch("http://127.0.0.1:80${uri}") with an in-process subrequest. */
    if (ngx_http_subrequest(r, &ctx->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    sr->method = NGX_HTTP_GET;
    ngx_str_set(&sr->method_name, "GET");

    return NGX_DONE;
}

/**
 * @brief load content post subrequest.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @param rc Subrequest completion status code.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_load_content_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t *pr;
    ngx_s3gw_load_content_ctx_t *ctx;
    ngx_int_t irc;
    ngx_uint_t status;

    ctx = data;
    pr = r->parent;

    if (pr == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    status = r->headers_out.status;
    if (status == 0) {
        if (rc == NGX_OK) {
            status = NGX_HTTP_OK;
        } else if (rc > 0) {
            status = (ngx_uint_t) rc;
        }
    }

    if (status == NGX_HTTP_OK) {
        irc = ngx_http_internal_redirect(pr, &ctx->uri, NULL);
    } else if (status == NGX_HTTP_NOT_FOUND) {
        irc = ngx_http_named_location(pr, &ngx_s3gw_named_s3_directory);
    } else {
        irc = ngx_http_named_location(pr, &ngx_s3gw_named_error500);
    }

    if (irc == NGX_ERROR) {
        ngx_http_finalize_request(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    return NGX_OK;
}

/**
 * @brief fetch credentials handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_fetch_credentials_handler(ngx_http_request_t *r)
{
    ngx_s3gw_credentials_t creds;
    ngx_int_t read_rc;
    uint64_t exp_ms;
    uint64_t now_ms;
    const char *access_key;
    const char *secret_key;

    ngx_memzero(&creds, sizeof(creds));

    access_key = getenv("AWS_ACCESS_KEY_ID");
    secret_key = getenv("AWS_SECRET_ACCESS_KEY");

    if (access_key != NULL && secret_key != NULL
        && access_key[0] != '\0'
        && secret_key[0] != '\0')
    {
        return ngx_s3gw_send_empty_status(r, NGX_HTTP_OK);
    }

    if (ngx_s3gw_ensure_now(r) != NGX_OK) {
        return ngx_s3gw_send_empty_status(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    read_rc = ngx_s3gw_read_credentials(r, &creds);
    if (read_rc == NGX_ERROR) {
        return ngx_s3gw_send_empty_status(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (read_rc == NGX_OK && creds.present && creds.has_expiration) {
        if (ngx_s3gw_parse_expiration_ms(&creds.expiration, &exp_ms) == NGX_OK) {
            now_ms = (uint64_t) ngx_s3gw_now_sec * 1000;
            if (exp_ms > NGX_S3GW_MAX_VALIDITY_OFFSET_MS
                && now_ms < (exp_ms - NGX_S3GW_MAX_VALIDITY_OFFSET_MS))
            {
                return ngx_s3gw_send_empty_status(r, NGX_HTTP_OK);
            }
        }
    }

    if (ngx_s3gw_fetch_credentials(r, &creds) != NGX_OK) {
        return ngx_s3gw_send_empty_status(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (ngx_s3gw_write_credentials(r, &creds) != NGX_OK) {
        return ngx_s3gw_send_empty_status(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    return ngx_s3gw_send_empty_status(r, NGX_HTTP_OK);
}

/**
 * @brief header filter.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_header_filter(ngx_http_request_t *r)
{
    ngx_s3gw_loc_conf_t *lcf;
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;
    ngx_str_t uri_path;
    ngx_str_t check_path;
    ngx_flag_t is_directory_head_request;
    ngx_str_t header_lc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_s3_gateway_c_module);
    if (lcf == NULL || !lcf->enable_header_filter) {
        return ngx_s3gw_next_header_filter(r);
    }

    is_directory_head_request = 0;
    if (ngx_s3gw_env.allow_listing
        && r->method == NGX_HTTP_HEAD
        && ngx_s3gw_get_uri_path(r, &uri_path) == NGX_OK)
    {
        check_path = uri_path;

        if (ngx_strlchr(uri_path.data, uri_path.data + uri_path.len, '%') != NULL) {
            if (ngx_s3gw_percent_decode(r->pool, &uri_path, &check_path) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (ngx_s3gw_is_directory(&check_path)) {
            is_directory_head_request = 1;
        }
    }

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (is_directory_head_request) {
            h[i].hash = 0;
            continue;
        }

        header_lc.len = h[i].key.len;
        header_lc.data = ngx_pnalloc(r->pool, header_lc.len);
        if (header_lc.data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(header_lc.data, h[i].key.data, h[i].key.len);

        if (!ngx_s3gw_header_should_be_allowed(&header_lc)
            && ngx_s3gw_header_should_be_stripped(&header_lc))
        {
            h[i].hash = 0;
        }
    }

    if (is_directory_head_request) {
        ngx_str_set(&r->headers_out.content_type, "text/html; charset=utf-8");
        r->headers_out.content_type_len = r->headers_out.content_type.len;
        r->headers_out.content_length_n = -1;
    }

    return ngx_s3gw_next_header_filter(r);
}

/**
 * @brief body filter.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param in Incoming chain for body-filter processing.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_s3gw_loc_conf_t *lcf;
    ngx_s3gw_body_ctx_t *ctx;
    ngx_chain_t *cl;
    ngx_flag_t has_last;
    ngx_flag_t needs_corruption;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_s3_gateway_c_module);
    if (lcf == NULL || !lcf->enable_body_filter || in == NULL) {
        return ngx_s3gw_next_body_filter(r, in);
    }

    if (!ngx_s3gw_env.four_404_on_empty_bucket) {
        return ngx_s3gw_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_s3_gateway_c_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_s3gw_body_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_s3_gateway_c_module);
    }

    if (!ctx->initialized) {
        ctx->initialized = 1;
        ctx->index_is_empty = ngx_s3gw_get_index_is_empty_initial(r);
    }

    has_last = 0;

    for (cl = in; cl; cl = cl->next) {
        size_t blen;

        if (cl->buf->last_buf || cl->buf->last_in_chain) {
            has_last = 1;
        }

        if (ctx->index_is_empty && ngx_buf_in_memory(cl->buf)) {
            blen = cl->buf->last - cl->buf->pos;
            if (ngx_strnstr(cl->buf->pos, "<Contents", blen) != NULL
                || ngx_strnstr(cl->buf->pos, "<CommonPrefixes", blen) != NULL)
            {
                ctx->index_is_empty = 0;
            }
        }
    }

    needs_corruption = (has_last && ctx->index_is_empty);
    if (!needs_corruption) {
        return ngx_s3gw_next_body_filter(r, in);
    }

    {
        ngx_chain_t *out_head = NULL;
        ngx_chain_t *out_tail = NULL;

        for (cl = in; cl; cl = cl->next) {
            ngx_chain_t *ncl = ngx_alloc_chain_link(r->pool);
            if (ncl == NULL) {
                return NGX_ERROR;
            }

            if (cl->buf->last_buf || cl->buf->last_in_chain) {
                ngx_buf_t *b = ngx_calloc_buf(r->pool);
                if (b == NULL) {
                    return NGX_ERROR;
                }
                b->pos = (u_char *) "junk";
                b->last = b->pos + 4;
                b->memory = 1;
                b->last_buf = cl->buf->last_buf;
                b->last_in_chain = cl->buf->last_in_chain;
                ncl->buf = b;
            } else {
                ncl->buf = cl->buf;
            }

            ncl->next = NULL;
            if (out_head == NULL) {
                out_head = ncl;
            } else {
                out_tail->next = ncl;
            }
            out_tail = ncl;
        }

        return ngx_s3gw_next_body_filter(r, out_head);
    }
}

#include "ngx_http_s3_gateway_c_helpers.c"
#include "ngx_http_s3_gateway_c_credentials.c"
#include "ngx_http_s3_gateway_c_signatures.c"
