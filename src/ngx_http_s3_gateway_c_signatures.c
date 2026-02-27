/**
 * @brief hmac raw.
 * @details Computes HMAC with the requested digest algorithm using OpenSSL's
 * modern EVP_MAC API on OpenSSL 3+ and falls back to HMAC() on older releases.
 * @param md OpenSSL digest algorithm descriptor.
 * @param key Cryptographic key or JSON field name used in lookup.
 * @param msg Message buffer used as HMAC/SHA input.
 * @param out Output buffer for raw digest bytes.
 * @param out_cap Capacity of output buffer in bytes.
 * @param out_len Number of bytes produced in the output buffer.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_hmac_raw(const EVP_MD *md, const ngx_str_t *key, const ngx_str_t *msg,
                  u_char *out, size_t out_cap, size_t *out_len)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[2];
    const char *digest_name;
    size_t len = 0;
    int ok;

    digest_name = EVP_MD_get0_name(md);
    if (digest_name == NULL) {
        return NGX_ERROR;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return NGX_ERROR;
    }

    ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *) digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    ok = EVP_MAC_init(ctx, key->data, key->len, params)
         && EVP_MAC_update(ctx, msg->data, msg->len)
         && EVP_MAC_final(ctx, out, &len, out_cap);

    EVP_MAC_CTX_free(ctx);

    if (!ok) {
        return NGX_ERROR;
    }

    *out_len = len;
    return NGX_OK;
#else
    unsigned int len;
    int key_len;

    if (key->len > INT_MAX) {
        return NGX_ERROR;
    }
    key_len = (int) key->len;

    if (HMAC(md, key->data, key_len, msg->data, msg->len, out, &len) == NULL) {
        return NGX_ERROR;
    }

    *out_len = (size_t) len;
    return NGX_OK;
#endif
}

/**
 * @brief hmac sha1 base64.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param key Cryptographic key or JSON field name used in lookup.
 * @param msg Message buffer used as HMAC/SHA input.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_hmac_sha1_base64(ngx_pool_t *pool, const ngx_str_t *key, const ngx_str_t *msg, ngx_str_t *out)
{
    size_t len;
    u_char digest[EVP_MAX_MD_SIZE];
    ngx_str_t src;
    ngx_str_t dst;

    if (ngx_s3gw_hmac_raw(EVP_sha1(), key, msg, digest, sizeof(digest), &len) != NGX_OK) {
        return NGX_ERROR;
    }

    src.data = digest;
    src.len = len;

    dst.len = ngx_base64_encoded_length(src.len);
    dst.data = ngx_pnalloc(pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&dst, &src);

    *out = dst;
    return NGX_OK;
}

/**
 * @brief hmac sha256 raw.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param key Cryptographic key or JSON field name used in lookup.
 * @param msg Message buffer used as HMAC/SHA input.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_hmac_sha256_raw(const ngx_str_t *key, const ngx_str_t *msg, u_char out[SHA256_DIGEST_LENGTH])
{
    size_t len;

    if (ngx_s3gw_hmac_raw(EVP_sha256(), key, msg, out, SHA256_DIGEST_LENGTH, &len) != NGX_OK) {
        return NGX_ERROR;
    }

    if (len != SHA256_DIGEST_LENGTH) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief hex encode.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param src Source byte/string buffer.
 * @param src_len Length of source buffer in bytes.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_hex_encode(ngx_pool_t *pool, const u_char *src, size_t src_len, ngx_str_t *out)
{
    static const u_char hex[] = "0123456789abcdef";
    size_t i;

    out->len = src_len * 2;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < src_len; i++) {
        out->data[i * 2] = hex[(src[i] >> 4) & 0x0f];
        out->data[i * 2 + 1] = hex[src[i] & 0x0f];
    }

    out->data[out->len] = '\0';
    return NGX_OK;
}

/**
 * @brief hmac sha256 hex.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param key Cryptographic key or JSON field name used in lookup.
 * @param msg Message buffer used as HMAC/SHA input.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_hmac_sha256_hex(ngx_pool_t *pool, const ngx_str_t *key, const ngx_str_t *msg, ngx_str_t *out)
{
    u_char digest[SHA256_DIGEST_LENGTH];

    if (ngx_s3gw_hmac_sha256_raw(key, msg, digest) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_s3gw_hex_encode(pool, digest, SHA256_DIGEST_LENGTH, out);
}

/**
 * @brief sha256 hex.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param msg Message buffer used as HMAC/SHA input.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_sha256_hex(ngx_pool_t *pool, const ngx_str_t *msg, ngx_str_t *out)
{
    u_char digest[SHA256_DIGEST_LENGTH];

    if (SHA256(msg->data, msg->len, digest) == NULL) {
        return NGX_ERROR;
    }

    return ngx_s3gw_hex_encode(pool, digest, SHA256_DIGEST_LENGTH, out);
}

/**
 * @brief signature v2.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param uri Canonical/request URI used for S3 operations or signing.
 * @param http_date RFC2616 date value used by Signature V2.
 * @param creds Credential structure to read, populate, or sign with.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_signature_v2(ngx_http_request_t *r,
                      const ngx_str_t *uri,
                      const ngx_str_t *http_date,
                      const ngx_s3gw_credentials_t *creds,
                      ngx_str_t *out)
{
    ngx_str_t string_to_sign;
    ngx_str_t signature;
    ngx_str_t prefix = ngx_string("AWS ");
    ngx_str_t colon = ngx_string(":");
    u_char *p;

    if (ngx_s3gw_ensure_now(r) != NGX_OK) {
        return NGX_ERROR;
    }

    string_to_sign.len = r->method_name.len + sizeof("\n\n\n") - 1 + http_date->len + 1 + uri->len;
    string_to_sign.data = ngx_pnalloc(r->pool, string_to_sign.len + 1);
    if (string_to_sign.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(string_to_sign.data, "%V\n\n\n%V\n%V", &r->method_name, http_date, uri);
    string_to_sign.len = p - string_to_sign.data;

    if (ngx_s3gw_hmac_sha1_base64(r->pool, &creds->secret_access_key, &string_to_sign, &signature) != NGX_OK) {
        return NGX_ERROR;
    }

    out->len = prefix.len + creds->access_key_id.len + colon.len + signature.len;
    out->data = ngx_pnalloc(r->pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(out->data, "%V%V:%V", &prefix, &creds->access_key_id, &signature);
    out->len = p - out->data;

    return NGX_OK;
}

/**
 * @brief split cached values.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param cached Serialized cached value containing date and signing-key payload.
 * @param date Date portion extracted from cached signing-key value.
 * @param payload Payload portion extracted from cache/JSON for further parsing.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_split_cached_values(const ngx_str_t *cached, ngx_str_t *date, ngx_str_t *payload)
{
    size_t i;

    if (cached == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < cached->len; i++) {
        if (cached->data[i] == ':') {
            date->data = cached->data;
            date->len = i;

            payload->data = cached->data + i + 1;
            payload->len = cached->len - i - 1;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

/**
 * @brief parse signing key json.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param payload Payload portion extracted from cache/JSON for further parsing.
 * @param out_key Output buffer for raw signing key bytes (32 bytes).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_parse_signing_key_json(const ngx_str_t *payload, u_char out_key[SHA256_DIGEST_LENGTH])
{
    const u_char *p;
    const u_char *end;
    const u_char *data_key;
    ngx_uint_t i;

    if (payload == NULL) {
        return NGX_ERROR;
    }

    end = payload->data + payload->len;
    data_key = (u_char *) "\"data\"";
    p = ngx_strnstr(payload->data, (char *) data_key, payload->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p += sizeof("\"data\"") - 1;

    while (p < end && isspace((unsigned char) *p)) {
        p++;
    }

    if (p >= end || *p != ':') {
        return NGX_ERROR;
    }

    p++;
    while (p < end && isspace((unsigned char) *p)) {
        p++;
    }

    if (p >= end || *p != '[') {
        return NGX_ERROR;
    }

    p++;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ngx_uint_t value = 0;
        ngx_flag_t has_digit = 0;

        while (p < end && isspace((unsigned char) *p)) {
            p++;
        }

        while (p < end && *p >= '0' && *p <= '9') {
            has_digit = 1;
            value = value * 10 + (*p - '0');
            if (value > 255) {
                return NGX_ERROR;
            }
            p++;
        }

        if (!has_digit) {
            return NGX_ERROR;
        }

        out_key[i] = (u_char) value;

        while (p < end && isspace((unsigned char) *p)) {
            p++;
        }

        if (i + 1 < SHA256_DIGEST_LENGTH) {
            if (p >= end || *p != ',') {
                return NGX_ERROR;
            }
            p++;
        } else {
            if (p >= end || *p != ']') {
                return NGX_ERROR;
            }
            p++;
        }
    }

    return NGX_OK;
}

/**
 * @brief build signing key cache value.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param pool Nginx memory pool used for allocations.
 * @param eight_date Date in YYYYMMDD form used by SigV4 key derivation.
 * @param key_raw Raw binary signing-key bytes before JSON serialization.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_build_signing_key_cache_value(ngx_pool_t *pool,
                                       const ngx_str_t *eight_date,
                                       const u_char key_raw[SHA256_DIGEST_LENGTH],
                                       ngx_str_t *out)
{
    ngx_uint_t i;
    u_char *p;

    out->len = eight_date->len
               + 1
               + sizeof("{\"type\":\"Buffer\",\"data\":[") - 1
               + sizeof("]}") - 1
               + SHA256_DIGEST_LENGTH * 3
               + (SHA256_DIGEST_LENGTH - 1);

    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(out->data, "%V:{\"type\":\"Buffer\",\"data\":[", eight_date);

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        p = ngx_sprintf(p, "%ui", (ngx_uint_t) key_raw[i]);
        if (i + 1 < SHA256_DIGEST_LENGTH) {
            *p++ = ',';
        }
    }

    *p++ = ']';
    *p++ = '}';
    *p = '\0';

    out->len = p - out->data;
    return NGX_OK;
}

/**
 * @brief signature v4.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param uri Canonical/request URI used for S3 operations or signing.
 * @param query_params Canonical query string used for SigV4/listing requests.
 * @param host S3 host value used in canonical headers.
 * @param creds Credential structure to read, populate, or sign with.
 * @param out Output parameter populated by this function.
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_signature_v4(ngx_http_request_t *r,
                      const ngx_str_t *uri,
                      const ngx_str_t *query_params,
                      const ngx_str_t *host,
                      const ngx_s3gw_credentials_t *creds,
                      ngx_str_t *out)
{
    ngx_str_t payload_hash;
    ngx_str_t signed_headers;
    ngx_str_t canonical_headers;
    ngx_str_t canonical_request;
    ngx_str_t canonical_request_hash;
    ngx_str_t scope;
    ngx_str_t string_to_sign;
    ngx_str_t k_secret;
    ngx_str_t k_date_msg;
    ngx_str_t k_region_msg;
    ngx_str_t k_service_msg;
    ngx_str_t k_signing_msg;
    ngx_str_t cache_enabled;
    ngx_str_t cached;
    ngx_str_t cached_date;
    ngx_str_t cached_payload;
    ngx_str_t cache_value;
    u_char k_date_raw[SHA256_DIGEST_LENGTH];
    u_char k_region_raw[SHA256_DIGEST_LENGTH];
    u_char k_service_raw[SHA256_DIGEST_LENGTH];
    u_char k_signing_raw[SHA256_DIGEST_LENGTH];
    ngx_flag_t cache_signing_key_enabled;
    ngx_flag_t use_cached_signing_key;
    ngx_str_t signing_key;
    ngx_str_t signature;
    u_char *p;

    if (ngx_s3gw_ensure_now(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_s3gw_payload_hash(r, &payload_hash) != NGX_OK) {
        return NGX_ERROR;
    }

    if (creds->has_session_token) {
        ngx_str_set(&signed_headers, "host;x-amz-content-sha256;x-amz-date;x-amz-security-token");

        canonical_headers.len = sizeof("host:\nx-amz-content-sha256:\nx-amz-date:\nx-amz-security-token:\n") - 1
                                + host->len + payload_hash.len + ngx_s3gw_now_amz_date.len
                                + creds->session_token.len;
        canonical_headers.data = ngx_pnalloc(r->pool, canonical_headers.len + 1);
        if (canonical_headers.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_sprintf(canonical_headers.data,
                        "host:%V\nx-amz-content-sha256:%V\nx-amz-date:%V\nx-amz-security-token:%V\n",
                        host,
                        &payload_hash,
                        &ngx_s3gw_now_amz_date,
                        &creds->session_token);
        canonical_headers.len = p - canonical_headers.data;

    } else {
        ngx_str_set(&signed_headers, "host;x-amz-content-sha256;x-amz-date");

        canonical_headers.len = sizeof("host:\nx-amz-content-sha256:\nx-amz-date:\n") - 1
                                + host->len + payload_hash.len + ngx_s3gw_now_amz_date.len;
        canonical_headers.data = ngx_pnalloc(r->pool, canonical_headers.len + 1);
        if (canonical_headers.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_sprintf(canonical_headers.data,
                        "host:%V\nx-amz-content-sha256:%V\nx-amz-date:%V\n",
                        host,
                        &payload_hash,
                        &ngx_s3gw_now_amz_date);
        canonical_headers.len = p - canonical_headers.data;
    }

    canonical_request.len = r->method_name.len + 1
                            + uri->len + 1
                            + query_params->len + 1
                            + canonical_headers.len + 1
                            + signed_headers.len + 1
                            + payload_hash.len;
    canonical_request.data = ngx_pnalloc(r->pool, canonical_request.len + 1);
    if (canonical_request.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(canonical_request.data,
                    "%V\n%V\n%V\n%V\n%V\n%V",
                    &r->method_name,
                    uri,
                    query_params,
                    &canonical_headers,
                    &signed_headers,
                    &payload_hash);
    canonical_request.len = p - canonical_request.data;

    if (ngx_s3gw_sha256_hex(r->pool, &canonical_request, &canonical_request_hash) != NGX_OK) {
        return NGX_ERROR;
    }

    scope.len = ngx_s3gw_now_eight_date.len + 1 + ngx_s3gw_env.s3_region.len + 1
                + ngx_s3gw_env.s3_service.len + sizeof("/aws4_request") - 1;
    scope.data = ngx_pnalloc(r->pool, scope.len + 1);
    if (scope.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(scope.data, "%V/%V/%V/aws4_request",
                    &ngx_s3gw_now_eight_date,
                    &ngx_s3gw_env.s3_region,
                    &ngx_s3gw_env.s3_service);
    scope.len = p - scope.data;

    string_to_sign.len = sizeof("AWS4-HMAC-SHA256\n") - 1
                         + ngx_s3gw_now_amz_date.len + 1
                         + scope.len + 1
                         + canonical_request_hash.len;
    string_to_sign.data = ngx_pnalloc(r->pool, string_to_sign.len + 1);
    if (string_to_sign.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(string_to_sign.data,
                    "AWS4-HMAC-SHA256\n%V\n%V\n%V",
                    &ngx_s3gw_now_amz_date,
                    &scope,
                    &canonical_request_hash);
    string_to_sign.len = p - string_to_sign.data;

    cache_signing_key_enabled = 0;
    if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_cache_signing_key_enabled, &cache_enabled) == NGX_OK
        && cache_enabled.len == 1
        && cache_enabled.data[0] == '1')
    {
        cache_signing_key_enabled = 1;
    }

    use_cached_signing_key = 0;
    if (cache_signing_key_enabled
        && ngx_s3gw_get_variable(r, &ngx_s3gw_var_signing_key_hash, &cached) == NGX_OK
        && ngx_s3gw_split_cached_values(&cached, &cached_date, &cached_payload) == NGX_OK
        && cached_date.len == ngx_s3gw_now_eight_date.len
        && ngx_strncmp(cached_date.data, ngx_s3gw_now_eight_date.data, cached_date.len) == 0)
    {
        if (ngx_s3gw_parse_signing_key_json(&cached_payload, k_signing_raw) != NGX_OK) {
            /* njs parity: ignore malformed cache and rebuild signing key. */
            use_cached_signing_key = 0;
        } else {
            use_cached_signing_key = 1;
        }
    }

    if (!use_cached_signing_key) {
        k_secret.len = sizeof("AWS4") - 1 + creds->secret_access_key.len;
        k_secret.data = ngx_pnalloc(r->pool, k_secret.len + 1);
        if (k_secret.data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_sprintf(k_secret.data, "AWS4%V", &creds->secret_access_key);
        k_secret.len = p - k_secret.data;

        k_date_msg = ngx_s3gw_now_eight_date;
        if (ngx_s3gw_hmac_sha256_raw(&k_secret, &k_date_msg, k_date_raw) != NGX_OK) {
            return NGX_ERROR;
        }

        k_region_msg = ngx_s3gw_env.s3_region;
        {
            ngx_str_t k_date_key;
            k_date_key.data = k_date_raw;
            k_date_key.len = SHA256_DIGEST_LENGTH;
            if (ngx_s3gw_hmac_sha256_raw(&k_date_key, &k_region_msg, k_region_raw) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        k_service_msg = ngx_s3gw_env.s3_service;
        {
            ngx_str_t k_region_key;
            k_region_key.data = k_region_raw;
            k_region_key.len = SHA256_DIGEST_LENGTH;
            if (ngx_s3gw_hmac_sha256_raw(&k_region_key, &k_service_msg, k_service_raw) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        ngx_str_set(&k_signing_msg, "aws4_request");
        {
            ngx_str_t k_service_key;
            k_service_key.data = k_service_raw;
            k_service_key.len = SHA256_DIGEST_LENGTH;
            if (ngx_s3gw_hmac_sha256_raw(&k_service_key, &k_signing_msg, k_signing_raw) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (cache_signing_key_enabled) {
            if (ngx_s3gw_build_signing_key_cache_value(r->pool, &ngx_s3gw_now_eight_date, k_signing_raw, &cache_value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ngx_s3gw_set_variable_by_index(r, ngx_s3gw_var_index_signing_key_hash, &cache_value) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    signing_key.data = k_signing_raw;
    signing_key.len = SHA256_DIGEST_LENGTH;

    if (ngx_s3gw_hmac_sha256_hex(r->pool, &signing_key, &string_to_sign, &signature) != NGX_OK) {
        return NGX_ERROR;
    }

    out->len = sizeof("AWS4-HMAC-SHA256 Credential=") - 1
               + creds->access_key_id.len + 1
               + scope.len
               + sizeof(",SignedHeaders=,Signature=") - 1
               + signed_headers.len
               + signature.len;
    out->data = ngx_pnalloc(r->pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(out->data,
                    "AWS4-HMAC-SHA256 Credential=%V/%V,SignedHeaders=%V,Signature=%V",
                    &creds->access_key_id,
                    &scope,
                    &signed_headers,
                    &signature);
    out->len = p - out->data;

    return NGX_OK;
}

/**
 * @brief var s3uri handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param v Nginx variable value structure that the handler fills.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_var_s3uri_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t uri;

    (void) data;

    if (ngx_s3gw_build_s3_uri(r, &uri) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_s3gw_set_var_value(r->pool, v, &uri);
}

/**
 * @brief var aws session token handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param v Nginx variable value structure that the handler fills.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_var_aws_session_token_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_s3gw_credentials_t creds;
    ngx_str_t empty = ngx_string("");

    (void) data;

    if (ngx_s3gw_read_credentials(r, &creds) == NGX_OK && creds.present && creds.has_session_token) {
        return ngx_s3gw_set_var_value(r->pool, v, &creds.session_token);
    }

    return ngx_s3gw_set_var_value(r->pool, v, &empty);
}

/**
 * @brief var s3auth handler.
 * @details Implements one step of the C gateway pipeline and preserves behavioral parity with the original njs module.
 * @param r Nginx HTTP request context.
 * @param v Nginx variable value structure that the handler fills.
 * @param data Opaque callback data from Nginx (unused unless noted).
 * @return NGX-style status code (for example NGX_OK/NGX_ERROR/NGX_DECLINED).
 */
static ngx_int_t
ngx_s3gw_var_s3auth_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_s3gw_credentials_t creds;
    ngx_str_t auth;
    ngx_str_t uri_path;
    ngx_str_t sig_uri;
    ngx_str_t query_params;
    ngx_str_t host;
    ngx_str_t base_uri;
    ngx_str_t http_date;
    ngx_flag_t for_index_page;

    (void) data;

    if (ngx_s3gw_ensure_now(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_s3gw_read_credentials(r, &creds) != NGX_OK || !creds.present) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_s3gw_env.aws_sigs_version.len == sizeof(NGX_S3GW_AWS_V2) - 1
        && ngx_strncmp(ngx_s3gw_env.aws_sigs_version.data,
                       NGX_S3GW_AWS_V2,
                       sizeof(NGX_S3GW_AWS_V2) - 1) == 0)
    {
        if (ngx_s3gw_get_uri_path(r, &uri_path) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (ngx_s3gw_is_directory(&uri_path)) {
            ngx_str_set(&sig_uri, "/");
        } else {
            sig_uri = uri_path;
        }

        for_index_page = ngx_s3gw_get_for_index_page(r);
        if (for_index_page && ngx_s3gw_is_directory(&uri_path)) {
            ngx_str_t index = ngx_string(NGX_S3GW_INDEX_PAGE);
            if (ngx_s3gw_concat2(r->pool, &uri_path, &index, &sig_uri) != NGX_OK) {
                v->not_found = 1;
                return NGX_OK;
            }
        }

        {
            ngx_str_t slash = ngx_string("/");
            ngx_str_t bucket_uri;

            if (ngx_s3gw_concat2(r->pool, &slash, &ngx_s3gw_env.s3_bucket_name, &bucket_uri) != NGX_OK
                || ngx_s3gw_concat2(r->pool, &bucket_uri, &sig_uri, &sig_uri) != NGX_OK)
            {
                v->not_found = 1;
                return NGX_OK;
            }
        }

        http_date = ngx_s3gw_now_http_date;

        if (ngx_s3gw_signature_v2(r, &sig_uri, &http_date, &creds, &auth) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }

        return ngx_s3gw_set_var_value(r->pool, v, &auth);
    }

    if (ngx_s3gw_get_variable(r, &ngx_s3gw_var_s3_host, &host) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    for_index_page = ngx_s3gw_get_for_index_page(r);

    if (ngx_s3gw_get_uri_path(r, &uri_path) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    /*
     * Keep njs parity: forIndexPage alters the directory-query probe via
     * uri_path + index.html, while canonical URI may still come from $s3uri.
     */
    if (for_index_page) {
        ngx_str_t index = ngx_string(NGX_S3GW_INDEX_PAGE);
        if (ngx_s3gw_concat2(r->pool, &uri_path, &index, &uri_path) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    if (ngx_s3gw_build_s3_dir_query_params(r, &uri_path, &query_params) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (query_params.len > 0) {
        if (ngx_s3gw_build_s3_base_uri(r->pool, &base_uri) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (base_uri.len > 0) {
            sig_uri = base_uri;
        } else {
            ngx_str_set(&sig_uri, "/");
        }
    } else {
        if (ngx_s3gw_build_s3_uri(r, &sig_uri) != NGX_OK) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    if (ngx_s3gw_signature_v4(r, &sig_uri, &query_params, &host, &creds, &auth) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_s3gw_set_var_value(r->pool, v, &auth);
}
