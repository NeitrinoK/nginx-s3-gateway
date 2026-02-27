/**
 * @brief read credentials from json.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param json JSON payload that is parsed by this helper.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_read_credentials_from_json(ngx_pool_t *pool, const ngx_str_t *json, ngx_s3gw_credentials_t *creds)
{
    if (ngx_s3gw_build_credentials_from_json(pool, json, creds) != NGX_OK) {
        return NGX_ERROR;
    }

    creds->present = 1;
    return NGX_OK;
}

/**
 * @brief read credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_read_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds)
{
    const char *access;
    const char *secret;
    const char *session;
    ngx_str_t value;
    ngx_str_t path;
    ngx_str_t json;

    ngx_memzero(creds, sizeof(*creds));

    access = getenv("AWS_ACCESS_KEY_ID");
    secret = getenv("AWS_SECRET_ACCESS_KEY");

    if (access != NULL && secret != NULL) {
        if (ngx_s3gw_env_set_str(r->pool, access, &creds->access_key_id) != NGX_OK
            || ngx_s3gw_env_set_str(r->pool, secret, &creds->secret_access_key) != NGX_OK)
        {
            return NGX_ERROR;
        }

        session = getenv("AWS_SESSION_TOKEN");
        if (session != NULL && session[0] != '\0') {
            if (ngx_s3gw_env_set_str(r->pool, session, &creds->session_token) != NGX_OK) {
                return NGX_ERROR;
            }
            creds->has_session_token = 1;
        }

        creds->present = 1;
        return NGX_OK;
    }

    if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_cache_instance_credentials_enabled, &value) == NGX_OK
        && value.len == 1 && value.data[0] == '1')
    {
        if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_instance_credential_json, &json) == NGX_OK
            && json.len > 0)
        {
            if (ngx_s3gw_read_credentials_from_json(r->pool, &json, creds) == NGX_OK) {
                return NGX_OK;
            }

            return NGX_DECLINED;
        }
        return NGX_DECLINED;
    }

    if (ngx_s3gw_credentials_temp_file(r->pool, &path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_read_file(r->pool, &path, &json) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_s3gw_read_credentials_from_json(r->pool, &json, creds) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief write credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_write_credentials(ngx_http_request_t *r, const ngx_s3gw_credentials_t *creds)
{
    const char *access;
    const char *secret;
    ngx_str_t empty = ngx_string("");
    ngx_str_t value;
    ngx_str_t path;
    ngx_str_t json;
    u_char *p;

    access = getenv("AWS_ACCESS_KEY_ID");
    secret = getenv("AWS_SECRET_ACCESS_KEY");

    if (access != NULL && secret != NULL && access[0] != '\0' && secret[0] != '\0') {
        return NGX_OK;
    }

    if (!creds->present) {
        return NGX_ERROR;
    }

    json.len = 200 + creds->access_key_id.len + creds->secret_access_key.len
               + creds->session_token.len + creds->expiration.len;
    json.data = ngx_pnalloc(r->pool, json.len);
    if (json.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(json.data,
                    "{\"accessKeyId\":\"%V\",\"secretAccessKey\":\"%V\",\"sessionToken\":\"%V\",\"expiration\":\"%V\"}",
                    &creds->access_key_id,
                    &creds->secret_access_key,
                    creds->has_session_token ? &creds->session_token : &empty,
                    creds->has_expiration ? &creds->expiration : &empty);

    json.len = p - json.data;

    if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_cache_instance_credentials_enabled, &value) == NGX_OK
        && value.len == 1 && value.data[0] == '1')
    {
        if (ngx_s3gw_set_variable_by_index(r, ngx_s3gw_var_index_instance_credential_json, &json) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (ngx_s3gw_credentials_temp_file(r->pool, &path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_write_file(&path, &json) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief fetch credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_fetch_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds)
{
    const char *ecs_rel;
    const char *web_identity_file;
    const char *eks_token_file;
    ngx_str_t uri;

    ecs_rel = getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    /* njs parity: areAllEnvVarsSet('VAR') checks presence, not non-empty value. */
    if (ecs_rel != NULL) {
        ngx_str_t base = ngx_string(NGX_S3GW_ECS_CREDENTIAL_BASE_URI);
        ngx_str_t rel;

        rel.data = (u_char *) ecs_rel;
        rel.len = ngx_strlen(ecs_rel);

        if (ngx_s3gw_concat2(r->pool, &base, &rel, &uri) != NGX_OK) {
            return NGX_ERROR;
        }

        return ngx_s3gw_fetch_ecs_role_credentials(r, &uri, creds);
    }

    web_identity_file = getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
    if (web_identity_file != NULL) {
        return ngx_s3gw_fetch_web_identity_credentials(r, creds);
    }

    eks_token_file = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    if (eks_token_file != NULL) {
        return ngx_s3gw_fetch_eks_pod_identity_credentials(r, creds);
    }

    return ngx_s3gw_fetch_ec2_role_credentials(r, creds);
}

/**
 * @brief http request.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param url Target URL for outbound metadata/STS request.
 * @param method HTTP method for outbound request.
 * @param headers Optional outbound header list for libcurl request.
 * @param resp Output HTTP response container filled by request helper.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_http_request(ngx_pool_t *pool, const ngx_str_t *url, const char *method,
                      struct curl_slist *headers, ngx_s3gw_http_response_t *resp)
{
    CURL *curl;
    CURLcode code;
    ngx_s3gw_curl_buffer_t buffer;
    u_char *urlz;

    curl = curl_easy_init();
    if (curl == NULL) {
        return NGX_ERROR;
    }

    buffer.data = NULL;
    buffer.len = 0;

    urlz = ngx_pnalloc(pool, url->len + 1);
    if (urlz == NULL) {
        curl_easy_cleanup(curl);
        return NGX_ERROR;
    }
    if (url->len > 0) {
        ngx_memcpy(urlz, url->data, url->len);
    }
    urlz[url->len] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, (char *) urlz);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    /*
     * Keep blocking window bounded: metadata/STS fetches run in worker context
     * and must fail fast under endpoint/network issues.
     */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, NGX_S3GW_CURL_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, NGX_S3GW_CURL_CONNECT_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ngx_s3gw_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

    if (headers != NULL) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        curl_easy_cleanup(curl);
        if (buffer.data != NULL) {
            free(buffer.data);
        }
        return NGX_ERROR;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp->status);

    resp->body = ngx_pnalloc(pool, buffer.len + 1);
    if (resp->body == NULL) {
        curl_easy_cleanup(curl);
        if (buffer.data != NULL) {
            free(buffer.data);
        }
        return NGX_ERROR;
    }

    if (buffer.len > 0) {
        ngx_memcpy(resp->body, buffer.data, buffer.len);
    }
    resp->body[buffer.len] = '\0';
    resp->body_len = buffer.len;

    curl_easy_cleanup(curl);
    if (buffer.data != NULL) {
        free(buffer.data);
    }

    return NGX_OK;
}

/**
 * @brief curl write cb.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param contents Incoming payload chunk from libcurl callback.
 * @param size Element size reported by libcurl callback.
 * @param nmemb Element count reported by libcurl callback.
 * @param userp User context pointer passed to libcurl callback.
 * @return Number of bytes processed.
 */
static size_t
ngx_s3gw_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize;
    ngx_s3gw_curl_buffer_t *mem;
    u_char *ptr;

    if (size != 0 && nmemb > SIZE_MAX / size) {
        return 0;
    }
    realsize = size * nmemb;
    mem = userp;

    if (mem->len > SIZE_MAX - realsize - 1) {
        return 0;
    }

    ptr = realloc(mem->data, mem->len + realsize + 1);
    if (ptr == NULL) {
        return 0;
    }

    mem->data = ptr;
    ngx_memcpy(mem->data + mem->len, contents, realsize);
    mem->len += realsize;
    mem->data[mem->len] = '\0';

    return realsize;
}

/**
 * @brief curl slist append safe.
 * @details Appends a header line and validates allocation success.
 * @param list Pointer to curl header list pointer.
 * @param line Header line to append.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_curl_slist_append_safe(struct curl_slist **list, const char *line)
{
    struct curl_slist *next;

    next = curl_slist_append(*list, line);
    if (next == NULL) {
        return NGX_ERROR;
    }

    *list = next;
    return NGX_OK;
}

/**
 * @brief json get string.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param json JSON payload that is parsed by this helper.
 * @param key Cryptographic key or JSON field name used in lookup.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_json_get_string(ngx_pool_t *pool, const ngx_str_t *json, const char *key, ngx_str_t *out)
{
    u_char *start;
    u_char *end;
    u_char *k;
    size_t key_len;

    key_len = ngx_strlen(key);
    k = (u_char *) key;

    start = json->data;
    end = json->data + json->len;

    while (start < end) {
        u_char *found;

        found = ngx_strnstr(start, (char *) k, end - start);
        if (found == NULL) {
            return NGX_DECLINED;
        }

        if (found == json->data || *(found - 1) != '"') {
            start = found + key_len;
            continue;
        }

        if (found + key_len >= end || *(found + key_len) != '"') {
            start = found + key_len;
            continue;
        }

        start = found + key_len + 1;
        while (start < end && *start != ':') {
            start++;
        }
        if (start >= end) {
            return NGX_DECLINED;
        }
        start++;

        while (start < end && isspace((unsigned char) *start)) {
            start++;
        }

        if (start >= end) {
            return NGX_DECLINED;
        }

        if (*start == '"') {
            u_char *value_start = ++start;
            while (start < end && *start != '"') {
                if (*start == '\\' && start + 1 < end) {
                    start += 2;
                    continue;
                }
                start++;
            }

            if (start >= end) {
                return NGX_DECLINED;
            }

            out->len = start - value_start;
            out->data = ngx_pnalloc(pool, out->len + 1);
            if (out->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(out->data, value_start, out->len);
            out->data[out->len] = '\0';
            return NGX_OK;
        }

        {
            u_char *value_start = start;
            while (start < end && *start != ',' && *start != '}') {
                start++;
            }

            out->len = start - value_start;
            out->data = ngx_pnalloc(pool, out->len + 1);
            if (out->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(out->data, value_start, out->len);
            out->data[out->len] = '\0';
            return ngx_s3gw_trim_whitespace(out);
        }
    }

    return NGX_DECLINED;
}

/**
 * @brief json get object.
 * @details Locates an object value by key and returns a slice that spans the
 * full object body including outer braces.
 * @param json JSON payload that is parsed by this helper.
 * @param key Cryptographic key or JSON field name used in lookup.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_json_get_object(const ngx_str_t *json, const char *key, ngx_str_t *out)
{
    u_char *start;
    u_char *end;
    u_char *k;
    size_t key_len;

    key_len = ngx_strlen(key);
    k = (u_char *) key;

    start = json->data;
    end = json->data + json->len;

    while (start < end) {
        u_char *found;
        u_char *q;
        u_char *p;
        u_char *obj_start;
        size_t depth;
        ngx_flag_t in_string;
        ngx_flag_t escaped;

        found = ngx_strnstr(start, (char *) k, end - start);
        if (found == NULL) {
            return NGX_DECLINED;
        }

        if (found == json->data || *(found - 1) != '"'
            || found + key_len >= end || *(found + key_len) != '"')
        {
            start = found + key_len;
            continue;
        }

        /*
         * Treat match as a JSON object key only if the preceding significant
         * character is '{' or ','. This avoids false matches inside values,
         * e.g. {"note":"AssumeRoleWithWebIdentityResponse", ...}.
         */
        q = found - 1;
        while (q > json->data && isspace((unsigned char) *(q - 1))) {
            q--;
        }

        if (q == json->data || (*(q - 1) != '{' && *(q - 1) != ',')) {
            start = found + key_len;
            continue;
        }

        p = found + key_len + 1;
        while (p < end && isspace((unsigned char) *p)) {
            p++;
        }

        if (p >= end || *p != ':') {
            start = found + key_len;
            continue;
        }

        p++;
        while (p < end && isspace((unsigned char) *p)) {
            p++;
        }

        if (p >= end || *p != '{') {
            start = found + key_len;
            continue;
        }

        obj_start = p;
        depth = 0;
        in_string = 0;
        escaped = 0;

        while (p < end) {
            u_char c = *p;

            if (in_string) {
                if (escaped) {
                    escaped = 0;
                } else if (c == '\\') {
                    escaped = 1;
                } else if (c == '"') {
                    in_string = 0;
                }

                p++;
                continue;
            }

            if (c == '"') {
                in_string = 1;
                p++;
                continue;
            }

            if (c == '{') {
                depth++;
            } else if (c == '}') {
                if (depth == 0) {
                    return NGX_ERROR;
                }

                depth--;
                if (depth == 0) {
                    out->data = obj_start;
                    out->len = (p + 1) - obj_start;
                    return NGX_OK;
                }
            }

            p++;
        }

        return NGX_ERROR;
    }

    return NGX_DECLINED;
}

/**
 * @brief build credentials from json.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param json JSON payload that is parsed by this helper.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_build_credentials_from_json(ngx_pool_t *pool, const ngx_str_t *json, ngx_s3gw_credentials_t *creds)
{
    ngx_memzero(creds, sizeof(*creds));

    if (ngx_s3gw_json_get_string(pool, json, "accessKeyId", &creds->access_key_id) != NGX_OK
        && ngx_s3gw_json_get_string(pool, json, "AccessKeyId", &creds->access_key_id) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_s3gw_json_get_string(pool, json, "secretAccessKey", &creds->secret_access_key) != NGX_OK
        && ngx_s3gw_json_get_string(pool, json, "SecretAccessKey", &creds->secret_access_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_s3gw_json_get_string(pool, json, "sessionToken", &creds->session_token) == NGX_OK
        || ngx_s3gw_json_get_string(pool, json, "SessionToken", &creds->session_token) == NGX_OK
        || ngx_s3gw_json_get_string(pool, json, "Token", &creds->session_token) == NGX_OK)
    {
        if (creds->session_token.len > 0) {
            creds->has_session_token = 1;
        }
    }

    if (ngx_s3gw_json_get_string(pool, json, "expiration", &creds->expiration) == NGX_OK
        || ngx_s3gw_json_get_string(pool, json, "Expiration", &creds->expiration) == NGX_OK)
    {
        if (creds->expiration.len > 0) {
            creds->has_expiration = 1;
        }
    }

    creds->present = 1;
    return NGX_OK;
}

/**
 * @brief fetch ecs role credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param uri Canonical/request URI used for S3 operations or signing.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_fetch_ecs_role_credentials(ngx_http_request_t *r, const ngx_str_t *uri, ngx_s3gw_credentials_t *creds)
{
    ngx_s3gw_http_response_t resp;
    ngx_str_t json;

    if (ngx_s3gw_http_request(r->pool, uri, "GET", NULL, &resp) != NGX_OK) {
        return NGX_ERROR;
    }

    if (resp.status < 200 || resp.status > 299) {
        return NGX_ERROR;
    }

    json.data = resp.body;
    json.len = resp.body_len;

    return ngx_s3gw_build_credentials_from_json(r->pool, &json, creds);
}

/**
 * @brief fetch ec2 role credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_fetch_ec2_role_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds)
{
    ngx_s3gw_http_response_t token_resp;
    ngx_s3gw_http_response_t name_resp;
    ngx_s3gw_http_response_t creds_resp;
    ngx_str_t token;
    ngx_str_t role_name;
    ngx_str_t url;
    ngx_str_t base;
    struct curl_slist *headers = NULL;
    ngx_str_t json;

    ngx_str_set(&url, NGX_S3GW_EC2_IMDS_TOKEN_ENDPOINT);

    if (ngx_s3gw_curl_slist_append_safe(&headers, "x-aws-ec2-metadata-token-ttl-seconds: 21600") != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_s3gw_http_request(r->pool, &url, "PUT", headers, &token_resp) != NGX_OK) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }
    curl_slist_free_all(headers);

    token.data = token_resp.body;
    token.len = token_resp.body_len;
    if (ngx_s3gw_trim_whitespace(&token) != NGX_OK || token.len == 0) {
        return NGX_ERROR;
    }

    {
        ngx_str_t hline;
        hline.len = sizeof("x-aws-ec2-metadata-token: ") - 1 + token.len;
        hline.data = ngx_pnalloc(r->pool, hline.len + 1);
        if (hline.data == NULL) {
            return NGX_ERROR;
        }

        ngx_sprintf(hline.data, "x-aws-ec2-metadata-token: %V", &token);

        headers = NULL;
        if (ngx_s3gw_curl_slist_append_safe(&headers, (char *) hline.data) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_str_set(&url, NGX_S3GW_EC2_IMDS_SECURITY_CREDENTIALS_ENDPOINT);
    if (ngx_s3gw_http_request(r->pool, &url, "GET", headers, &name_resp) != NGX_OK) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }

    role_name.data = name_resp.body;
    role_name.len = name_resp.body_len;
    if (ngx_s3gw_trim_whitespace(&role_name) != NGX_OK || role_name.len == 0) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }

    ngx_str_set(&base, NGX_S3GW_EC2_IMDS_SECURITY_CREDENTIALS_ENDPOINT);
    if (ngx_s3gw_concat2(r->pool, &base, &role_name, &url) != NGX_OK) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }

    if (ngx_s3gw_http_request(r->pool, &url, "GET", headers, &creds_resp) != NGX_OK) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }

    curl_slist_free_all(headers);

    json.data = creds_resp.body;
    json.len = creds_resp.body_len;

    return ngx_s3gw_build_credentials_from_json(r->pool, &json, creds);
}

/**
 * @brief fetch eks pod identity credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_fetch_eks_pod_identity_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds)
{
    const char *token_file;
    ngx_str_t token_path;
    ngx_str_t token;
    ngx_str_t url;
    struct curl_slist *headers = NULL;
    ngx_str_t hline;
    ngx_s3gw_http_response_t resp;
    ngx_str_t json;

    token_file = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    if (token_file == NULL || token_file[0] == '\0') {
        return NGX_ERROR;
    }

    if (ngx_s3gw_env_set_str(r->pool, token_file, &token_path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_read_file(r->pool, &token_path, &token) != NGX_OK) {
        return NGX_ERROR;
    }

    hline.len = sizeof("Authorization: ") - 1 + token.len;
    hline.data = ngx_pnalloc(r->pool, hline.len + 1);
    if (hline.data == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(hline.data, "Authorization: %V", &token);
    headers = NULL;
    if (ngx_s3gw_curl_slist_append_safe(&headers, (char *) hline.data) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_str_set(&url, NGX_S3GW_EKS_POD_IDENTITY_AGENT_CREDENTIALS_ENDPOINT);
    if (ngx_s3gw_http_request(r->pool, &url, "GET", headers, &resp) != NGX_OK) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }

    curl_slist_free_all(headers);

    json.data = resp.body;
    json.len = resp.body_len;

    return ngx_s3gw_build_credentials_from_json(r->pool, &json, creds);
}

/**
 * @brief fetch web identity credentials.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param creds Credential structure to read, populate, or sign with.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_fetch_web_identity_credentials(ngx_http_request_t *r, ngx_s3gw_credentials_t *creds)
{
    const char *arn;
    const char *name;
    const char *token_file;
    const char *sts_endpoint;
    const char *sts_regional;
    const char *region;
    ngx_str_t token_path;
    ngx_str_t token;
    ngx_str_t endpoint;
    ngx_str_t query;
    ngx_str_t url;
    ngx_s3gw_http_response_t resp;
    struct curl_slist *headers = NULL;
    ngx_str_t json;
    ngx_str_t response_obj;
    ngx_str_t result_obj;
    ngx_str_t credentials_obj;

    arn = getenv("AWS_ROLE_ARN");
    name = getenv("AWS_ROLE_SESSION_NAME");
    token_file = getenv("AWS_WEB_IDENTITY_TOKEN_FILE");

    if (arn == NULL || name == NULL || token_file == NULL) {
        return NGX_ERROR;
    }

    sts_endpoint = getenv("STS_ENDPOINT");
    if (sts_endpoint == NULL || sts_endpoint[0] == '\0') {
        sts_regional = getenv("AWS_STS_REGIONAL_ENDPOINTS");
        if (sts_regional != NULL
            && ngx_strlen(sts_regional) == sizeof("regional") - 1
            && ngx_strncmp(sts_regional, "regional", sizeof("regional") - 1) == 0)
        {
            region = getenv("AWS_REGION");
            if (region == NULL || region[0] == '\0') {
                return NGX_ERROR;
            }

            endpoint.len = sizeof("https://sts..amazonaws.com") - 1 + ngx_strlen(region);
            endpoint.data = ngx_pnalloc(r->pool, endpoint.len + 1);
            if (endpoint.data == NULL) {
                return NGX_ERROR;
            }

            ngx_sprintf(endpoint.data, "https://sts.%s.amazonaws.com", region);
            endpoint.len = ngx_strlen(endpoint.data);
        } else {
            ngx_str_set(&endpoint, "https://sts.amazonaws.com");
        }
    } else {
        if (ngx_s3gw_env_set_str(r->pool, sts_endpoint, &endpoint) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_s3gw_env_set_str(r->pool, token_file, &token_path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_read_file(r->pool, &token_path, &token) != NGX_OK) {
        return NGX_ERROR;
    }

    {
        ngx_str_t arn_raw;
        ngx_str_t name_raw;
        ngx_str_t arn_enc;
        ngx_str_t name_enc;
        ngx_str_t token_enc;

        if (ngx_s3gw_env_set_str(r->pool, arn, &arn_raw) != NGX_OK
            || ngx_s3gw_env_set_str(r->pool, name, &name_raw) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_s3gw_encode_uri_component(r->pool, &arn_raw, &arn_enc) != NGX_OK
            || ngx_s3gw_encode_uri_component(r->pool, &name_raw, &name_enc) != NGX_OK
            || ngx_s3gw_encode_uri_component(r->pool, &token, &token_enc) != NGX_OK)
        {
            return NGX_ERROR;
        }

        query.len = sizeof("Version=2011-06-15&Action=AssumeRoleWithWebIdentity&RoleArn=&RoleSessionName=&WebIdentityToken=") - 1
                    + arn_enc.len + name_enc.len + token_enc.len;
        query.data = ngx_pnalloc(r->pool, query.len + 1);
        if (query.data == NULL) {
            return NGX_ERROR;
        }

        ngx_sprintf(query.data,
                    "Version=2011-06-15&Action=AssumeRoleWithWebIdentity&RoleArn=%V&RoleSessionName=%V&WebIdentityToken=%V",
                    &arn_enc, &name_enc, &token_enc);
        query.len = ngx_strlen(query.data);
    }

    {
        ngx_str_t qm = ngx_string("?");
        if (ngx_s3gw_concat3(r->pool, &endpoint, &qm, &query, &url) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    headers = NULL;
    if (ngx_s3gw_curl_slist_append_safe(&headers, "Accept: application/json") != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_s3gw_http_request(r->pool, &url, "GET", headers, &resp) != NGX_OK) {
        curl_slist_free_all(headers);
        return NGX_ERROR;
    }

    curl_slist_free_all(headers);

    json.data = resp.body;
    json.len = resp.body_len;

    /*
     * Keep njs parity for STS payload shape:
     * AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials
     */
    if (ngx_s3gw_json_get_object(&json, "AssumeRoleWithWebIdentityResponse", &response_obj) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_json_get_object(&response_obj, "AssumeRoleWithWebIdentityResult", &result_obj) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_json_get_object(&result_obj, "Credentials", &credentials_obj) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_s3gw_build_credentials_from_json(r->pool, &credentials_obj, creds);
}

/**
 * @brief parse expiration ms.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param expiration Credential expiration value (epoch seconds or ISO8601).
 * @param out_ms Parsed expiration timestamp in milliseconds.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_parse_expiration_ms(const ngx_str_t *expiration, uint64_t *out_ms)
{
    ngx_uint_t i;
    ngx_flag_t all_digits = 1;

    if (expiration == NULL || expiration->len == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < expiration->len; i++) {
        if (!isdigit(expiration->data[i])) {
            all_digits = 0;
            break;
        }
    }

    if (all_digits) {
        ngx_int_t sec = ngx_atoi(expiration->data, expiration->len);
        if (sec == NGX_ERROR) {
            return NGX_ERROR;
        }
        *out_ms = (uint64_t) sec * 1000;
        return NGX_OK;
    }

    {
        int year, mon, day, hour, min, sec;
        struct tm tmv;
        time_t epoch;

        if (sscanf((char *) expiration->data,
                   "%d-%d-%dT%d:%d:%d",
                   &year, &mon, &day, &hour, &min, &sec) != 6)
        {
            return NGX_ERROR;
        }

        ngx_memzero(&tmv, sizeof(struct tm));
        tmv.tm_year = year - 1900;
        tmv.tm_mon = mon - 1;
        tmv.tm_mday = day;
        tmv.tm_hour = hour;
        tmv.tm_min = min;
        tmv.tm_sec = sec;

        epoch = timegm(&tmv);
        if (epoch == (time_t) -1) {
            return NGX_ERROR;
        }

        *out_ms = (uint64_t) epoch * 1000;
        return NGX_OK;
    }
}

/**
 * @brief read file.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param path Filesystem or URI path value being processed.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_read_file(ngx_pool_t *pool, const ngx_str_t *path, ngx_str_t *out)
{
    int fd;
    off_t size;
    u_char *buf;
    ssize_t n;

    fd = open((char *) path->data, O_RDONLY);
    if (fd < 0) {
        return NGX_ERROR;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        close(fd);
        return NGX_ERROR;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(pool, size + 1);
    if (buf == NULL) {
        close(fd);
        return NGX_ERROR;
    }

    n = read(fd, buf, size);
    close(fd);

    if (n < 0) {
        return NGX_ERROR;
    }

    buf[n] = '\0';

    out->data = buf;
    out->len = n;
    return NGX_OK;
}

/**
 * @brief write file.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param path Filesystem or URI path value being processed.
 * @param content Content bytes/string to persist.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_write_file(const ngx_str_t *path, const ngx_str_t *content)
{
    int fd;
    ssize_t n;
    size_t written;
    char *target;
    char *tmp;
    size_t tmp_cap;
    int rc;
    int saved_errno;

    target = malloc(path->len + 1);
    if (target == NULL) {
        return NGX_ERROR;
    }
    if (path->len > 0) {
        memcpy(target, path->data, path->len);
    }
    target[path->len] = '\0';

    tmp_cap = path->len + 64;
    tmp = malloc(tmp_cap);
    if (tmp == NULL) {
        free(target);
        return NGX_ERROR;
    }

    if (snprintf(tmp, tmp_cap, "%s.tmp.%d.%lu", target, (int) getpid(), (unsigned long) ngx_time()) <= 0) {
        free(tmp);
        free(target);
        return NGX_ERROR;
    }

    fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, 0600);
    if (fd < 0) {
        free(tmp);
        free(target);
        return NGX_ERROR;
    }

    written = 0;
    while (written < content->len) {
        n = write(fd, content->data + written, content->len - written);
        if (n < 0) {
            saved_errno = errno;
            close(fd);
            unlink(tmp);
            free(tmp);
            free(target);
            errno = saved_errno;
            return NGX_ERROR;
        }
        written += (size_t) n;
    }

    if (close(fd) < 0) {
        unlink(tmp);
        free(tmp);
        free(target);
        return NGX_ERROR;
    }

    rc = rename(tmp, target);
    saved_errno = errno;
    if (rc != 0) {
        unlink(tmp);
        free(tmp);
        free(target);
        errno = saved_errno;
        return NGX_ERROR;
    }

    free(tmp);
    free(target);
    return NGX_OK;
}

/**
 * @brief credentials temp file.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param path Filesystem or URI path value being processed.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_credentials_temp_file(ngx_pool_t *pool, ngx_str_t *path)
{
    const char *custom;
    const char *tmpdir;
    ngx_str_t slash = ngx_string("/");
    ngx_str_t suffix = ngx_string("credentials.json");
    ngx_str_t base;

    custom = getenv("AWS_CREDENTIALS_TEMP_FILE");
    if (custom != NULL && custom[0] != '\0') {
        return ngx_s3gw_env_set_str(pool, custom, path);
    }

    tmpdir = getenv("TMPDIR");
    if (tmpdir != NULL && tmpdir[0] != '\0') {
        if (ngx_s3gw_env_set_str(pool, tmpdir, &base) != NGX_OK) {
            return NGX_ERROR;
        }
        return ngx_s3gw_concat3(pool, &base, &slash, &suffix, path);
    }

    ngx_str_set(path, "/tmp/credentials.json");
    return NGX_OK;
}

/**
 * @brief trim whitespace.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param value Value being parsed, normalized, or tested.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_trim_whitespace(ngx_str_t *value)
{
    size_t start = 0;
    size_t end = value->len;

    while (start < value->len && isspace((unsigned char) value->data[start])) {
        start++;
    }

    while (end > start && isspace((unsigned char) value->data[end - 1])) {
        end--;
    }

    value->data += start;
    value->len = end - start;

    return NGX_OK;
}
