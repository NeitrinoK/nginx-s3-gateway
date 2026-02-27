/**
 * @brief parse boolean str.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param value Value being parsed, normalized, or tested.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_parse_boolean_str(const ngx_str_t *value)
{
    if (value == NULL || value->data == NULL) {
        return 0;
    }

    if ((value->len == 4 && ngx_strncmp(value->data, "TRUE", 4) == 0)
        || (value->len == 4 && ngx_strncmp(value->data, "true", 4) == 0)
        || (value->len == 4 && ngx_strncmp(value->data, "True", 4) == 0)
        || (value->len == 3 && ngx_strncmp(value->data, "YES", 3) == 0)
        || (value->len == 3 && ngx_strncmp(value->data, "yes", 3) == 0)
        || (value->len == 3 && ngx_strncmp(value->data, "Yes", 3) == 0)
        || (value->len == 1 && value->data[0] == '1'))
    {
        return 1;
    }

    return 0;
}

/**
 * @brief parse boolean cstr.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param value Value being parsed, normalized, or tested.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_parse_boolean_cstr(const char *value)
{
    ngx_str_t s;

    if (value == NULL) {
        return 0;
    }

    s.data = (u_char *) value;
    s.len = ngx_strlen(value);
    return ngx_s3gw_parse_boolean_str(&s);
}

/**
 * @brief env set str.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param raw Raw C string input (typically from environment variables).
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_env_set_str(ngx_pool_t *pool, const char *raw, ngx_str_t *out)
{
    size_t len;

    len = ngx_strlen(raw);
    out->data = ngx_pnalloc(pool, len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(out->data, raw, len);
    out->data[len] = '\0';
    out->len = len;
    return NGX_OK;
}

/**
 * @brief parse semicolon array.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param raw Raw C string input (typically from environment variables).
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_parse_semicolon_array(ngx_pool_t *pool, const char *raw, ngx_array_t **out)
{
    ngx_array_t *arr;
    size_t len;
    size_t i;
    size_t start;

    arr = ngx_array_create(pool, 4, sizeof(ngx_str_t));
    if (arr == NULL) {
        return NGX_ERROR;
    }

    if (raw == NULL || raw[0] == '\0' || (raw[0] == ';' && raw[1] == '\0')) {
        *out = arr;
        return NGX_OK;
    }

    len = ngx_strlen(raw);
    /* Keep njs parseArray parity: trim only one trailing delimiter before split. */
    if (len > 0 && raw[len - 1] == ';') {
        len--;
    }

    start = 0;
    for (i = 0; i <= len; i++) {
        if (i == len || raw[i] == ';') {
            ngx_str_t *item;
            size_t tlen;

            tlen = i - start;
            item = ngx_array_push(arr);
            if (item == NULL) {
                return NGX_ERROR;
            }

            item->data = ngx_pnalloc(pool, tlen + 1);
            if (item->data == NULL) {
                return NGX_ERROR;
            }

            if (tlen > 0) {
                ngx_memcpy(item->data, raw + start, tlen);
            }
            item->data[tlen] = '\0';
            item->len = tlen;

            start = i + 1;
        }
    }

    *out = arr;
    return NGX_OK;
}

/**
 * @brief init env.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_init_env(ngx_conf_t *cf)
{
    const char *required[] = {
        "S3_BUCKET_NAME",
        "S3_SERVER",
        "S3_SERVER_PROTO",
        "S3_SERVER_PORT",
        "S3_REGION",
        "AWS_SIGS_VERSION",
        "S3_STYLE"
    };
    const char *required_values[sizeof(required) / sizeof(required[0])];

    const char *service;
    const char *strip;
    const char *allow;
    ngx_uint_t i;
    ngx_pool_t *pool;

    if (ngx_s3gw_env.inited) {
        return NGX_OK;
    }

    pool = cf->cycle->pool;

    for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        required_values[i] = getenv(required[i]);
        if (required_values[i] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "s3gw: required environment variable %s is missing", required[i]);
            return NGX_ERROR;
        }
    }

    ngx_memzero(&ngx_s3gw_env, sizeof(ngx_s3gw_env));

    if (ngx_s3gw_env_set_str(pool, required_values[0], &ngx_s3gw_env.s3_bucket_name) != NGX_OK
        || ngx_s3gw_env_set_str(pool, required_values[1], &ngx_s3gw_env.s3_server) != NGX_OK
        || ngx_s3gw_env_set_str(pool, required_values[2], &ngx_s3gw_env.s3_server_proto) != NGX_OK
        || ngx_s3gw_env_set_str(pool, required_values[3], &ngx_s3gw_env.s3_server_port) != NGX_OK
        || ngx_s3gw_env_set_str(pool, required_values[4], &ngx_s3gw_env.s3_region) != NGX_OK
        || ngx_s3gw_env_set_str(pool, required_values[5], &ngx_s3gw_env.aws_sigs_version) != NGX_OK
        || ngx_s3gw_env_set_str(pool, required_values[6], &ngx_s3gw_env.s3_style) != NGX_OK)
    {
        return NGX_ERROR;
    }

    service = getenv("S3_SERVICE");
    if (service == NULL || service[0] == '\0') {
        service = NGX_S3GW_SERVICE_DEFAULT;
    }

    if (ngx_s3gw_env_set_str(pool, service, &ngx_s3gw_env.s3_service) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_s3gw_env.debug = ngx_s3gw_parse_boolean_cstr(getenv("DEBUG"));
    ngx_s3gw_env.allow_listing = ngx_s3gw_parse_boolean_cstr(getenv("ALLOW_DIRECTORY_LIST"));
    ngx_s3gw_env.provide_index_page = ngx_s3gw_parse_boolean_cstr(getenv("PROVIDE_INDEX_PAGE"));
    ngx_s3gw_env.append_slash = ngx_s3gw_parse_boolean_cstr(getenv("APPEND_SLASH_FOR_POSSIBLE_DIRECTORY"));
    ngx_s3gw_env.four_404_on_empty_bucket = ngx_s3gw_parse_boolean_cstr(getenv("FOUR_O_FOUR_ON_EMPTY_BUCKET"));

    strip = getenv("HEADER_PREFIXES_TO_STRIP");
    if (ngx_s3gw_parse_semicolon_array(pool, strip, &ngx_s3gw_env.header_prefixes_to_strip) != NGX_OK) {
        return NGX_ERROR;
    }

    allow = getenv("HEADER_PREFIXES_ALLOWED");
    if (ngx_s3gw_parse_semicolon_array(pool, allow, &ngx_s3gw_env.header_prefixes_allowed) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_s3gw_env.inited = 1;
    return NGX_OK;
}

/**
 * @brief init now strings.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cf Nginx configuration context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_init_now_strings(ngx_conf_t *cf)
{
    u_char *http_date;
    u_char *eight;
    u_char *amz;
    struct tm tms;

    ngx_s3gw_now_sec = ngx_time();

    http_date = ngx_pnalloc(cf->cycle->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"));
    if (http_date == NULL) {
        return NGX_ERROR;
    }

    ngx_http_time(http_date, ngx_s3gw_now_sec);
    http_date[sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1] = '\0';
    ngx_s3gw_now_http_date.data = http_date;
    ngx_s3gw_now_http_date.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;

    if (gmtime_r(&ngx_s3gw_now_sec, &tms) == NULL) {
        return NGX_ERROR;
    }

    eight = ngx_pnalloc(cf->cycle->pool, 9);
    if (eight == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(eight, 9, "%04d%02d%02d",
                 tms.tm_year + 1900, tms.tm_mon + 1, tms.tm_mday);
    eight[8] = '\0';

    ngx_s3gw_now_eight_date.data = eight;
    ngx_s3gw_now_eight_date.len = 8;

    amz = ngx_pnalloc(cf->cycle->pool, 17);
    if (amz == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(amz, 17, "%VT%02d%02d%02dZ",
                 &ngx_s3gw_now_eight_date,
                 tms.tm_hour, tms.tm_min, tms.tm_sec);
    amz[16] = '\0';

    ngx_s3gw_now_amz_date.data = amz;
    ngx_s3gw_now_amz_date.len = 16;

    return NGX_OK;
}

/**
 * @brief ensure now values.
 * @details Initializes and reuses per-request timestamp strings so all handlers
 * within a single request use consistent signing dates.
 * @param r Nginx HTTP request context.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_ensure_now(ngx_http_request_t *r)
{
    ngx_s3gw_body_ctx_t *ctx;
    u_char *http_date;
    u_char *eight;
    u_char *amz;
    struct tm tms;

    ctx = ngx_http_get_module_ctx(r, ngx_http_s3_gateway_c_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_s3gw_body_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_s3_gateway_c_module);
    }

    if (!ctx->now_initialized) {
        ctx->now_sec = ngx_time();

        http_date = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"));
        if (http_date == NULL) {
            return NGX_ERROR;
        }

        ngx_http_time(http_date, ctx->now_sec);
        http_date[sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1] = '\0';
        ctx->now_http_date.data = http_date;
        ctx->now_http_date.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;

        if (gmtime_r(&ctx->now_sec, &tms) == NULL) {
            return NGX_ERROR;
        }

        eight = ngx_pnalloc(r->pool, 9);
        if (eight == NULL) {
            return NGX_ERROR;
        }
        ngx_snprintf(eight, 9, "%04d%02d%02d",
                     tms.tm_year + 1900, tms.tm_mon + 1, tms.tm_mday);
        eight[8] = '\0';
        ctx->now_eight_date.data = eight;
        ctx->now_eight_date.len = 8;

        amz = ngx_pnalloc(r->pool, 17);
        if (amz == NULL) {
            return NGX_ERROR;
        }
        ngx_snprintf(amz, 17, "%VT%02d%02d%02dZ",
                     &ctx->now_eight_date,
                     tms.tm_hour, tms.tm_min, tms.tm_sec);
        amz[16] = '\0';
        ctx->now_amz_date.data = amz;
        ctx->now_amz_date.len = 16;

        ctx->now_initialized = 1;
    }

    ngx_s3gw_now_sec = ctx->now_sec;
    ngx_s3gw_now_http_date = ctx->now_http_date;
    ngx_s3gw_now_eight_date = ctx->now_eight_date;
    ngx_s3gw_now_amz_date = ctx->now_amz_date;

    return NGX_OK;
}

/**
 * @brief get variable.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param name Variable or field name used by the helper.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_get_variable(ngx_http_request_t *r, const ngx_str_t *name, ngx_str_t *out)
{
    ngx_http_variable_value_t *vv;

    vv = ngx_http_get_variable(r, (ngx_str_t *) name, ngx_hash_key_lc(name->data, name->len));
    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    out->data = vv->data;
    out->len = vv->len;
    return NGX_OK;
}

/**
 * @brief get variable dual.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param a First input string segment.
 * @param b Second input string segment.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_get_variable_dual(ngx_http_request_t *r, const ngx_str_t *a, const ngx_str_t *b, ngx_str_t *out)
{
    if (ngx_s3gw_get_variable(r, a, out) == NGX_OK) {
        return NGX_OK;
    }

    return ngx_s3gw_get_variable(r, b, out);
}

/**
 * @brief set variable by index.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param index Indexed-variable slot in nginx variable table.
 * @param value Value being parsed, normalized, or tested.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_set_variable_by_index(ngx_http_request_t *r, ngx_int_t index, const ngx_str_t *value)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_variable_t *variables;
    ngx_http_variable_value_t vv;
    ngx_http_variable_value_t *dst;

    if (index == NGX_ERROR || index == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    if (cmcf == NULL || (ngx_uint_t) index >= cmcf->variables.nelts) {
        return NGX_DECLINED;
    }

    variables = cmcf->variables.elts;

    vv.len = value->len;
    vv.valid = 1;
    vv.no_cacheable = 0;
    vv.not_found = 0;
    vv.escape = 0;
    vv.data = value->data;

    if (variables[index].set_handler != NULL) {
        variables[index].set_handler(r, &vv, variables[index].data);
        return NGX_OK;
    }

    dst = ngx_http_get_indexed_variable(r, index);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    *dst = vv;
    return NGX_OK;
}

/**
 * @brief get uri path.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_get_uri_path(ngx_http_request_t *r, ngx_str_t *out)
{
    if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_uri_path, out) == NGX_OK) {
        return NGX_OK;
    }

    *out = r->uri;
    return NGX_OK;
}

/**
 * @brief get for index page.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_get_for_index_page(ngx_http_request_t *r)
{
    ngx_str_t value;

    if (ngx_s3gw_get_variable_dual(r,
                                   &ngx_s3gw_var_for_index_page,
                                   &ngx_s3gw_var_for_index_page_lc,
                                   &value) != NGX_OK)
    {
        return 0;
    }

    return ngx_s3gw_parse_boolean_str(&value);
}

/**
 * @brief get index is empty initial.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_get_index_is_empty_initial(ngx_http_request_t *r)
{
    ngx_str_t value;

    if (ngx_s3gw_get_variable_dual(r,
                                   &ngx_s3gw_var_index_is_empty,
                                   &ngx_s3gw_var_index_is_empty_lc,
                                   &value) != NGX_OK)
    {
        return 0;
    }

    return ngx_s3gw_parse_boolean_str(&value);
}

/**
 * @brief is directory.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param path Filesystem or URI path value being processed.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_is_directory(const ngx_str_t *path)
{
    if (path == NULL || path->len == 0) {
        return 0;
    }

    return path->data[path->len - 1] == '/';
}

/**
 * @brief ends with.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param value Value being parsed, normalized, or tested.
 * @param suffix Expected suffix literal used in comparison.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_ends_with(const ngx_str_t *value, const char *suffix)
{
    size_t suffix_len;

    suffix_len = ngx_strlen(suffix);
    if (value->len < suffix_len) {
        return 0;
    }

    return ngx_strncmp(value->data + value->len - suffix_len, suffix, suffix_len) == 0;
}

/**
 * @brief hex to nibble.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param c Byte/character value to classify.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_hex_to_nibble(u_char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

/**
 * @brief percent decode.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param src Source byte/string buffer.
 * @param dst Destination string buffer.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_percent_decode(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst)
{
    u_char *out;
    size_t i;
    size_t j;

    out = ngx_pnalloc(pool, src->len + 1);
    if (out == NULL) {
        return NGX_ERROR;
    }

    for (i = 0, j = 0; i < src->len; i++) {
        if (src->data[i] == '%') {
            ngx_int_t hi;
            ngx_int_t lo;

            if (i + 2 >= src->len) {
                return NGX_ERROR;
            }

            hi = ngx_s3gw_hex_to_nibble(src->data[i + 1]);
            lo = ngx_s3gw_hex_to_nibble(src->data[i + 2]);

            if (hi < 0 || lo < 0) {
                return NGX_ERROR;
            }

            out[j++] = (u_char) ((hi << 4) | lo);
            i += 2;
            continue;
        }

        out[j++] = src->data[i];
    }

    dst->data = out;
    dst->len = j;
    dst->data[j] = '\0';
    return NGX_OK;
}

/**
 * @brief is unreserved.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param c Byte/character value to classify.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_is_unreserved(u_char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return 1;
    }

    return (c == '-' || c == '_' || c == '.' || c == '~');
}

/**
 * @brief encode uri component.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param src Source byte/string buffer.
 * @param dst Destination string buffer.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_encode_uri_component(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst)
{
    static const u_char hex[] = "0123456789ABCDEF";
    u_char *out;
    size_t i;
    size_t j;

    if (src->len > (SIZE_MAX - 1) / 3) {
        return NGX_ERROR;
    }

    out = ngx_pnalloc(pool, src->len * 3 + 1);
    if (out == NULL) {
        return NGX_ERROR;
    }

    for (i = 0, j = 0; i < src->len; i++) {
        u_char c = src->data[i];
        if (ngx_s3gw_is_unreserved(c)) {
            out[j++] = c;
        } else {
            out[j++] = '%';
            out[j++] = hex[(c >> 4) & 0x0f];
            out[j++] = hex[c & 0x0f];
        }
    }

    dst->data = out;
    dst->len = j;
    dst->data[j] = '\0';
    return NGX_OK;
}

/**
 * @brief escape uri path.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param src Source byte/string buffer.
 * @param dst Destination string buffer.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_escape_uri_path(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst)
{
    static const u_char hex[] = "0123456789ABCDEF";
    ngx_str_t decoded;
    const ngx_str_t *input;
    ngx_flag_t has_percent;
    u_char *out;
    size_t i;
    size_t j;

    has_percent = (ngx_strlchr(src->data, src->data + src->len, '%') != NULL);

    if (has_percent) {
        if (ngx_s3gw_percent_decode(pool, src, &decoded) != NGX_OK) {
            return NGX_ERROR;
        }
        input = &decoded;
    } else {
        input = src;
    }

    if (input->len > (SIZE_MAX - 1) / 3) {
        return NGX_ERROR;
    }

    out = ngx_pnalloc(pool, input->len * 3 + 1);
    if (out == NULL) {
        return NGX_ERROR;
    }

    for (i = 0, j = 0; i < input->len; i++) {
        u_char c = input->data[i];
        if (c == '/' || ngx_s3gw_is_unreserved(c)) {
            out[j++] = c;
        } else {
            out[j++] = '%';
            out[j++] = hex[(c >> 4) & 0x0f];
            out[j++] = hex[c & 0x0f];
        }
    }

    dst->data = out;
    dst->len = j;
    dst->data[j] = '\0';
    return NGX_OK;
}

/**
 * @brief concat2.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param a First input string segment.
 * @param b Second input string segment.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_concat2(ngx_pool_t *pool, const ngx_str_t *a, const ngx_str_t *b, ngx_str_t *out)
{
    size_t a_len = a->len;
    size_t b_len = b->len;
    const u_char *a_data = a->data;
    const u_char *b_data = b->data;

    out->len = a_len + b_len;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(out->data, a_data, a_len);
    ngx_memcpy(out->data + a_len, b_data, b_len);
    out->data[out->len] = '\0';

    return NGX_OK;
}

/**
 * @brief concat3.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param a First input string segment.
 * @param b Second input string segment.
 * @param c Third input string segment.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_concat3(ngx_pool_t *pool, const ngx_str_t *a, const ngx_str_t *b, const ngx_str_t *c, ngx_str_t *out)
{
    size_t a_len = a->len;
    size_t b_len = b->len;
    size_t c_len = c->len;
    const u_char *a_data = a->data;
    const u_char *b_data = b->data;
    const u_char *c_data = c->data;

    out->len = a_len + b_len + c_len;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(out->data, a_data, a_len);
    ngx_memcpy(out->data + a_len, b_data, b_len);
    ngx_memcpy(out->data + a_len + b_len, c_data, c_len);
    out->data[out->len] = '\0';

    return NGX_OK;
}

/**
 * @brief build s3 base uri.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_build_s3_base_uri(ngx_pool_t *pool, ngx_str_t *out)
{
    if (ngx_s3gw_env.s3_style.len == sizeof(NGX_S3GW_S3_STYLE_PATH) - 1
        && ngx_strncmp(ngx_s3gw_env.s3_style.data,
                       NGX_S3GW_S3_STYLE_PATH,
                       sizeof(NGX_S3GW_S3_STYLE_PATH) - 1) == 0)
    {
        ngx_str_t slash = ngx_string("/");
        return ngx_s3gw_concat2(pool, &slash, &ngx_s3gw_env.s3_bucket_name, out);
    }

    out->data = (u_char *) "";
    out->len = 0;
    return NGX_OK;
}

/**
 * @brief build s3 dir query params.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param uri_path URI path used to derive S3 listing query parameters.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_build_s3_dir_query_params(ngx_http_request_t *r, const ngx_str_t *uri_path, ngx_str_t *out)
{
    ngx_str_t decoded;
    ngx_str_t no_leading;
    ngx_str_t encoded;
    ngx_str_t prefix = ngx_string("&prefix=");
    ngx_str_t base = ngx_string("delimiter=%2F");

    if (!ngx_s3gw_is_directory(uri_path) || r->method != NGX_HTTP_GET) {
        out->data = (u_char *) "";
        out->len = 0;
        return NGX_OK;
    }

    if (ngx_s3gw_ends_with(uri_path, NGX_S3GW_INDEX_PAGE)) {
        out->data = (u_char *) "";
        out->len = 0;
        return NGX_OK;
    }

    if (uri_path->len == 1 && uri_path->data[0] == '/') {
        *out = base;
        return NGX_OK;
    }

    if (ngx_s3gw_percent_decode(r->pool, uri_path, &decoded) != NGX_OK) {
        return NGX_ERROR;
    }

    no_leading = decoded;
    if (no_leading.len > 0 && no_leading.data[0] == '/') {
        no_leading.data++;
        no_leading.len--;
    }

    if (ngx_s3gw_encode_uri_component(r->pool, &no_leading, &encoded) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_concat3(r->pool, &base, &prefix, &encoded, out) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief build s3 uri.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_build_s3_uri(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_str_t uri_path;
    ngx_str_t base_path;
    ngx_str_t query_params;
    ngx_str_t joined;
    ngx_str_t escaped;
    ngx_flag_t for_index_page;

    if (ngx_s3gw_get_uri_path(r, &uri_path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_build_s3_base_uri(r->pool, &base_path) != NGX_OK) {
        return NGX_ERROR;
    }

    for_index_page = ngx_s3gw_get_for_index_page(r);

    if (ngx_s3gw_env.allow_listing && !for_index_page) {
        if (ngx_s3gw_build_s3_dir_query_params(r, &uri_path, &query_params) != NGX_OK) {
            return NGX_ERROR;
        }

        if (query_params.len > 0) {
            ngx_str_t qm = ngx_string("?");
            if (ngx_s3gw_concat3(r->pool, &base_path, &qm, &query_params, out) != NGX_OK) {
                return NGX_ERROR;
            }
        } else {
            if (ngx_s3gw_concat2(r->pool, &base_path, &uri_path, &joined) != NGX_OK) {
                return NGX_ERROR;
            }
            if (ngx_s3gw_escape_uri_path(r->pool, &joined, &escaped) != NGX_OK) {
                return NGX_ERROR;
            }
            *out = escaped;
        }

        ngx_s3gw_debug_log(r, "S3 Request URI: %V %V", &r->method_name, out);
        return NGX_OK;
    }

    if (ngx_s3gw_env.provide_index_page && ngx_s3gw_is_directory(&uri_path)) {
        ngx_str_t index = ngx_string(NGX_S3GW_INDEX_PAGE);
        if (ngx_s3gw_concat2(r->pool, &uri_path, &index, &uri_path) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_s3gw_concat2(r->pool, &base_path, &uri_path, &joined) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_escape_uri_path(r->pool, &joined, &escaped) != NGX_OK) {
        return NGX_ERROR;
    }

    *out = escaped;

    ngx_s3gw_debug_log(r, "S3 Request URI: %V %V", &r->method_name, out);
    return NGX_OK;
}

/**
 * @brief header contains.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param header_lc Lowercased header name being evaluated.
 * @param needle Header token/prefix to match.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_header_contains(const ngx_str_t *header_lc, const ngx_str_t *needle)
{
    u_char *pos;

    /* Keep njs parity: ''.indexOf('', 0) == 0, so empty token matches any header. */
    if (needle->len == 0) {
        return 1;
    }

    if (header_lc->len < needle->len) {
        return 0;
    }

    pos = ngx_strnstr(header_lc->data, (char *) needle->data, header_lc->len);
    return pos != NULL;
}

/**
 * @brief header should be allowed.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param header_lc Lowercased header name being evaluated.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_header_should_be_allowed(const ngx_str_t *header_lc)
{
    ngx_str_t *items;
    ngx_uint_t i;

    if (ngx_s3gw_env.header_prefixes_allowed == NULL) {
        return 0;
    }

    items = ngx_s3gw_env.header_prefixes_allowed->elts;
    for (i = 0; i < ngx_s3gw_env.header_prefixes_allowed->nelts; i++) {
        if (ngx_s3gw_header_contains(header_lc, &items[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief header should be stripped.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param header_lc Lowercased header name being evaluated.
 * @return Boolean flag value: 1 for true, 0 for false.
 */
static ngx_flag_t
ngx_s3gw_header_should_be_stripped(const ngx_str_t *header_lc)
{
    ngx_str_t *items;
    ngx_uint_t i;
    ngx_str_t amz = ngx_string("x-amz-");

    if (ngx_s3gw_header_contains(header_lc, &amz)) {
        return 1;
    }

    if (ngx_s3gw_env.header_prefixes_to_strip == NULL) {
        return 0;
    }

    items = ngx_s3gw_env.header_prefixes_to_strip->elts;
    for (i = 0; i < ngx_s3gw_env.header_prefixes_to_strip->nelts; i++) {
        if (ngx_s3gw_header_contains(header_lc, &items[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief set var value.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param v Nginx variable value structure that the handler fills.
 * @param value Value being parsed, normalized, or tested.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_set_var_value(ngx_pool_t *pool, ngx_http_variable_value_t *v, const ngx_str_t *value)
{
    u_char *data;

    data = ngx_pnalloc(pool, value->len);
    if (data == NULL && value->len > 0) {
        return NGX_ERROR;
    }

    if (value->len > 0) {
        ngx_memcpy(data, value->data, value->len);
    }

    v->data = data;
    v->len = value->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

/**
 * @brief var http date handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param v Nginx variable value structure that the handler fills.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_var_http_date_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    (void) data;

    if (ngx_s3gw_ensure_now(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_s3gw_set_var_value(r->pool, v, &ngx_s3gw_now_http_date);
}

/**
 * @brief var aws date handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param v Nginx variable value structure that the handler fills.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_var_aws_date_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    (void) data;

    if (ngx_s3gw_ensure_now(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_s3gw_set_var_value(r->pool, v, &ngx_s3gw_now_amz_date);
}

/**
 * @brief payload hash.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_payload_hash(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_str_t body;

    if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_request_body, &body) != NGX_OK) {
        body.data = (u_char *) "";
        body.len = 0;
    }

    return ngx_s3gw_sha256_hex(r->pool, &body, out);
}

/**
 * @brief var aws payload hash handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param v Nginx variable value structure that the handler fills.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_var_aws_payload_hash_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t hash;

    (void) data;

    if (ngx_s3gw_payload_hash(r, &hash) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_s3gw_set_var_value(r->pool, v, &hash);
}
