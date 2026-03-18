#include "hitls_cert_compress.h"

#include <string.h>

#ifdef HITLS_HAVE_ZLIB
#include <zlib.h>
#endif

#define HITLS_MAX_REGISTERED_METHODS 8

static HITLS_CertCompressMethod g_methods[HITLS_MAX_REGISTERED_METHODS];
static size_t g_method_count = 0;

static int HitlsSimpleRleCompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    size_t in_idx = 0;
    size_t out_idx = 0;

    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    while (in_idx < in_len) {
        uint8_t value = in[in_idx];
        size_t run = 1;
        while ((in_idx + run) < in_len && in[in_idx + run] == value && run < 255U) {
            run++;
        }

        if (out_idx + 2U > *out_len) {
            return -1;
        }

        out[out_idx++] = (uint8_t)run;
        out[out_idx++] = value;
        in_idx += run;
    }

    *out_len = out_idx;
    return 0;
}

static int HitlsSimpleRleDecompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    size_t in_idx = 0;
    size_t out_idx = 0;

    if (in == NULL || out == NULL || out_len == NULL || (in_len % 2U) != 0U) {
        return -1;
    }

    while (in_idx + 1U < in_len) {
        size_t run = in[in_idx++];
        uint8_t value = in[in_idx++];
        size_t i;

        if (run == 0U || out_idx + run > *out_len) {
            return -1;
        }

        for (i = 0; i < run; i++) {
            out[out_idx++] = value;
        }
    }

    *out_len = out_idx;
    return 0;
}

#ifdef HITLS_HAVE_ZLIB
static int HitlsZlibCompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    uLongf z_out_len;
    int zrc;

    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (in_len > (size_t)0xFFFFFFFFu || *out_len > (size_t)0xFFFFFFFFu) {
        return -1;
    }

    z_out_len = (uLongf)(*out_len);
    zrc = compress2((Bytef *)out, &z_out_len, (const Bytef *)in, (uLong)in_len, Z_BEST_SPEED);
    if (zrc != Z_OK) {
        return -1;
    }
    *out_len = (size_t)z_out_len;
    return 0;
}

static int HitlsZlibDecompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    uLongf z_out_len;
    int zrc;

    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (in_len > (size_t)0xFFFFFFFFu || *out_len > (size_t)0xFFFFFFFFu) {
        return -1;
    }

    z_out_len = (uLongf)(*out_len);
    zrc = uncompress((Bytef *)out, &z_out_len, (const Bytef *)in, (uLong)in_len);
    if (zrc != Z_OK) {
        return -1;
    }
    *out_len = (size_t)z_out_len;
    return 0;
}
#endif

void HITLS_CertCompressCtxInit(HITLS_CertCompressCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->min_compress_len = HITLS_CERT_COMPRESS_DEFAULT_THRESHOLD;
}

int HITLS_CertCompressEnable(HITLS_CertCompressCtx *ctx, uint16_t algorithm, uint8_t enabled)
{
    size_t i;
    if (ctx == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    for (i = 0; i < ctx->algo_count; i++) {
        if (ctx->algos[i].algorithm == algorithm) {
            ctx->algos[i].enabled = enabled;
            return HITLS_CERT_COMPRESS_OK;
        }
    }

    if (ctx->algo_count >= sizeof(ctx->algos) / sizeof(ctx->algos[0])) {
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    ctx->algos[ctx->algo_count].algorithm = algorithm;
    ctx->algos[ctx->algo_count].enabled = enabled;
    ctx->algo_count++;

    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_CertCompressIsEnabled(const HITLS_CertCompressCtx *ctx, uint16_t algorithm)
{
    size_t i;
    if (ctx == NULL) {
        return 0;
    }

    for (i = 0; i < ctx->algo_count; i++) {
        if (ctx->algos[i].algorithm == algorithm) {
            return ctx->algos[i].enabled;
        }
    }

    return 0;
}

int HITLS_RegisterDefaultCertCompressionMethods(void)
{
    HITLS_CertCompressMethod zlib_method;
    HITLS_CertCompressMethod brotli_method = {
        HITLS_CERT_COMPRESS_BROTLI, "brotli-demo-rle", HitlsSimpleRleCompress, HitlsSimpleRleDecompress
    };
    HITLS_CertCompressMethod zstd_method = {
        HITLS_CERT_COMPRESS_ZSTD, "zstd-demo-rle", HitlsSimpleRleCompress, HitlsSimpleRleDecompress
    };
    int rc;

#ifdef HITLS_HAVE_ZLIB
    zlib_method.algorithm = HITLS_CERT_COMPRESS_ZLIB;
    zlib_method.name = "zlib";
    zlib_method.compress = HitlsZlibCompress;
    zlib_method.decompress = HitlsZlibDecompress;
#else
    zlib_method.algorithm = HITLS_CERT_COMPRESS_ZLIB;
    zlib_method.name = "zlib-demo-rle";
    zlib_method.compress = HitlsSimpleRleCompress;
    zlib_method.decompress = HitlsSimpleRleDecompress;
#endif

    rc = HITLS_RegisterCertCompression(&zlib_method);
    if (rc != HITLS_CERT_COMPRESS_OK) {
        return rc;
    }
    rc = HITLS_RegisterCertCompression(&brotli_method);
    if (rc != HITLS_CERT_COMPRESS_OK) {
        return rc;
    }
    return HITLS_RegisterCertCompression(&zstd_method);
}

int HITLS_RegisterCertCompression(const HITLS_CertCompressMethod *method)
{
    if (method == NULL || method->compress == NULL || method->decompress == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    if (HITLS_GetCertCompression(method->algorithm) != NULL) {
        return HITLS_CERT_COMPRESS_OK;
    }

    if (g_method_count >= HITLS_MAX_REGISTERED_METHODS) {
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    g_methods[g_method_count++] = *method;
    return HITLS_CERT_COMPRESS_OK;
}

const HITLS_CertCompressMethod *HITLS_GetCertCompression(uint16_t algorithm)
{
    size_t i;
    for (i = 0; i < g_method_count; i++) {
        if (g_methods[i].algorithm == algorithm) {
            return &g_methods[i];
        }
    }
    return NULL;
}

int HITLS_ParseCompressCertificateExtension(HITLS_CertCompressCtx *ctx,
                                            const uint8_t *ext_data,
                                            size_t ext_len)
{
    size_t i;
    if (ctx == NULL || ext_data == NULL || ext_len == 0U || (ext_len % 2U) != 0U) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    ctx->peer_algo_count = 0;
    for (i = 0; i + 1 < ext_len; i += 2) {
        uint16_t algo = (uint16_t)((ext_data[i] << 8) | ext_data[i + 1]);
        if (ctx->peer_algo_count >= sizeof(ctx->peer_algos) / sizeof(ctx->peer_algos[0])) {
            return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
        }
        ctx->peer_algos[ctx->peer_algo_count].algorithm = algo;
        ctx->peer_algos[ctx->peer_algo_count].enabled = 1;
        ctx->peer_algo_count++;
    }

    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_BuildCompressCertificateExtension(const HITLS_CertCompressCtx *ctx,
                                            uint8_t *out,
                                            size_t *out_len)
{
    size_t i;
    size_t enabled_count = 0;
    size_t required;

    if (ctx == NULL || out_len == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    for (i = 0; i < ctx->algo_count; i++) {
        if (ctx->algos[i].enabled != 0U) {
            enabled_count++;
        }
    }

    required = enabled_count * 2U;
    if (required == 0U) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }

    if (out == NULL || *out_len < required) {
        *out_len = required;
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    required = 0;
    for (i = 0; i < ctx->algo_count; i++) {
        if (ctx->algos[i].enabled == 0U) {
            continue;
        }
        out[required++] = (uint8_t)(ctx->algos[i].algorithm >> 8);
        out[required++] = (uint8_t)(ctx->algos[i].algorithm & 0xFFU);
    }

    *out_len = required;
    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_SelectCommonCertCompression(HITLS_CertCompressCtx *ctx,
                                      const uint16_t *server_priority,
                                      size_t server_priority_len,
                                      uint16_t *selected_algorithm)
{
    size_t i;
    size_t j;

    if (ctx == NULL || server_priority == NULL || server_priority_len == 0U) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    for (i = 0; i < server_priority_len; i++) {
        uint16_t candidate = server_priority[i];
        if (!HITLS_CertCompressIsEnabled(ctx, candidate)) {
            continue;
        }
        for (j = 0; j < ctx->peer_algo_count; j++) {
            if (ctx->peer_algos[j].algorithm == candidate && ctx->peer_algos[j].enabled != 0U) {
                ctx->selected_algorithm = candidate;
                if (selected_algorithm != NULL) {
                    *selected_algorithm = candidate;
                }
                return HITLS_CERT_COMPRESS_OK;
            }
        }
    }

    return HITLS_CERT_COMPRESS_ERR_NO_COMMON_ALGO;
}

int HITLS_ShouldSendCompressedCertificate(const HITLS_CertCompressCtx *ctx,
                                          size_t cert_msg_len)
{
    if (ctx == NULL || ctx->selected_algorithm == 0U) {
        return 0;
    }

    if (cert_msg_len < (size_t)ctx->min_compress_len) {
        return 0;
    }

    if (ctx->send_compressed_by_default != 0U) {
        return 1;
    }

    return cert_msg_len >= HITLS_CERT_COMPRESS_DEFAULT_THRESHOLD;
}

int HITLS_CompressCertificateMessage(const HITLS_CertCompressCtx *ctx,
                                     uint16_t algorithm,
                                     const uint8_t *cert_msg,
                                     size_t cert_msg_len,
                                     uint8_t *out,
                                     size_t *out_len,
                                     uint32_t *uncompressed_len)
{
    const HITLS_CertCompressMethod *method;

    if (ctx == NULL || cert_msg == NULL || out == NULL || out_len == NULL || uncompressed_len == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    if (cert_msg_len > HITLS_CERT_COMPRESS_MAX_UNCOMPRESSED_LEN) {
        return HITLS_CERT_COMPRESS_ERR_LIMIT;
    }

    if (!HITLS_CertCompressIsEnabled(ctx, algorithm)) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }

    method = HITLS_GetCertCompression(algorithm);
    if (method == NULL) {
        return HITLS_CERT_COMPRESS_ERR_NOT_FOUND;
    }

    *uncompressed_len = (uint32_t)cert_msg_len;
    if (method->compress(cert_msg, cert_msg_len, out, out_len) != 0) {
        return HITLS_CERT_COMPRESS_ERR_ENCODE;
    }

    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_DecompressCertificateMessage(uint16_t algorithm,
                                       const uint8_t *compressed,
                                       size_t compressed_len,
                                       uint8_t *out,
                                       size_t *out_len,
                                       uint32_t expected_uncompressed_len)
{
    const HITLS_CertCompressMethod *method;

    if (compressed == NULL || out == NULL || out_len == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    if (expected_uncompressed_len > HITLS_CERT_COMPRESS_MAX_UNCOMPRESSED_LEN) {
        return HITLS_CERT_COMPRESS_ERR_LIMIT;
    }

    method = HITLS_GetCertCompression(algorithm);
    if (method == NULL) {
        return HITLS_CERT_COMPRESS_ERR_NOT_FOUND;
    }

    if (*out_len < expected_uncompressed_len) {
        *out_len = expected_uncompressed_len;
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    if (method->decompress(compressed, compressed_len, out, out_len) != 0) {
        return HITLS_CERT_COMPRESS_ERR_DECODE;
    }

    if (*out_len != expected_uncompressed_len) {
        return HITLS_CERT_COMPRESS_ERR_DECODE;
    }

    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_BuildCompressedCertificateHandshake(uint16_t algorithm,
                                              uint32_t uncompressed_len,
                                              const uint8_t *compressed,
                                              size_t compressed_len,
                                              uint8_t *out,
                                              size_t *out_len)
{
    size_t required = 5U + compressed_len;

    if (compressed == NULL || out_len == NULL || uncompressed_len > HITLS_CERT_COMPRESS_MAX_UNCOMPRESSED_LEN) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    if (out == NULL || *out_len < required) {
        *out_len = required;
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    out[0] = (uint8_t)(algorithm >> 8);
    out[1] = (uint8_t)(algorithm & 0xFFU);
    out[2] = (uint8_t)((uncompressed_len >> 16) & 0xFFU);
    out[3] = (uint8_t)((uncompressed_len >> 8) & 0xFFU);
    out[4] = (uint8_t)(uncompressed_len & 0xFFU);

    if (compressed_len > 0U) {
        memcpy(out + 5, compressed, compressed_len);
    }

    *out_len = required;
    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_ParseCompressedCertificateHandshake(const uint8_t *in,
                                              size_t in_len,
                                              HITLS_CompressedCertificate *msg)
{
    if (in == NULL || msg == NULL || in_len < 5U) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    msg->selected_algorithm = (uint16_t)((in[0] << 8) | in[1]);
    msg->uncompressed_len = ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 8) | in[4];
    if (msg->uncompressed_len > HITLS_CERT_COMPRESS_MAX_UNCOMPRESSED_LEN) {
        return HITLS_CERT_COMPRESS_ERR_LIMIT;
    }

    msg->compressed_cert_msg = in + 5;
    msg->compressed_cert_msg_len = in_len - 5U;
    return HITLS_CERT_COMPRESS_OK;
}

void HITLS_SSL_CTX_Init(HITLS_SSL_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    HITLS_CertCompressCtxInit(&ctx->cert_compress);
    ctx->cert_compression_enabled = 1U;
}

int HITLS_SSL_CTX_set_cert_compression_enabled(HITLS_SSL_CTX *ctx, uint8_t onoff)
{
    if (ctx == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    ctx->cert_compression_enabled = (onoff != 0U) ? 1U : 0U;
    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_SSL_CTX_add_cert_compression_alg(HITLS_SSL_CTX *ctx, uint16_t algorithm)
{
    if (ctx == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    return HITLS_CertCompressEnable(&ctx->cert_compress, algorithm, 1U);
}

void HITLS_SSL_Init(HITLS_SSL *ssl, HITLS_SSL_CTX *ctx)
{
    if (ssl == NULL) {
        return;
    }
    memset(ssl, 0, sizeof(*ssl));
    ssl->ctx = ctx;
    if (ctx != NULL) {
        ssl->cert_compress = ctx->cert_compress;
        ssl->cert_compression_enabled = ctx->cert_compression_enabled;
    } else {
        HITLS_CertCompressCtxInit(&ssl->cert_compress);
        ssl->cert_compression_enabled = 1U;
    }
}

int HITLS_SSL_set_cert_compression_enabled(HITLS_SSL *ssl, uint8_t onoff)
{
    if (ssl == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    ssl->cert_compression_enabled = (onoff != 0U) ? 1U : 0U;
    ssl->has_local_enable_override = 1U;
    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_SSL_add_cert_compression_alg(HITLS_SSL *ssl, uint16_t algorithm)
{
    if (ssl == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    return HITLS_CertCompressEnable(&ssl->cert_compress, algorithm, 1U);
}

int HITLS_SSL_build_clienthello_cert_compress_ext(const HITLS_SSL *ssl, uint8_t *out, size_t *out_len)
{
    if (ssl == NULL || out_len == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    if (ssl->cert_compression_enabled == 0U) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }
    return HITLS_BuildCompressCertificateExtension(&ssl->cert_compress, out, out_len);
}

int HITLS_SSL_parse_peer_cert_compress_ext(HITLS_SSL *ssl, const uint8_t *ext_data, size_t ext_len)
{
    if (ssl == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    if (ssl->cert_compression_enabled == 0U) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }
    return HITLS_ParseCompressCertificateExtension(&ssl->cert_compress, ext_data, ext_len);
}

int HITLS_SSL_negotiate_cert_compression(HITLS_SSL *ssl,
                                         const uint16_t *server_priority,
                                         size_t server_priority_len)
{
    if (ssl == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    if (ssl->cert_compression_enabled == 0U) {
        ssl->cert_compress.selected_algorithm = 0U;
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }
    return HITLS_SelectCommonCertCompression(&ssl->cert_compress, server_priority, server_priority_len, NULL);
}

int HITLS_SSL_get_negotiated_cert_compression(const HITLS_SSL *ssl, uint16_t *algorithm)
{
    if (ssl == NULL || algorithm == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    *algorithm = ssl->cert_compress.selected_algorithm;
    return (*algorithm == 0U) ? HITLS_CERT_COMPRESS_ERR_NOT_FOUND : HITLS_CERT_COMPRESS_OK;
}

int HITLS_SSL_compress_certificate(HITLS_SSL *ssl,
                                   const uint8_t *cert_msg,
                                   size_t cert_msg_len,
                                   uint8_t *out,
                                   size_t *out_len,
                                   uint32_t *uncompressed_len)
{
    int rc;
    if (ssl == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    if (ssl->cert_compression_enabled == 0U) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }
    if (HITLS_ShouldSendCompressedCertificate(&ssl->cert_compress, cert_msg_len) == 0) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }

    rc = HITLS_CompressCertificateMessage(&ssl->cert_compress,
                                          ssl->cert_compress.selected_algorithm,
                                          cert_msg,
                                          cert_msg_len,
                                          out,
                                          out_len,
                                          uncompressed_len);
    if (rc == HITLS_CERT_COMPRESS_OK) {
        ssl->cert_compress.last_uncompressed_len = *uncompressed_len;
        ssl->cert_compress.last_compressed_len = (uint32_t)(*out_len);
    }
    return rc;
}

int HITLS_SSL_decompress_certificate(const HITLS_SSL *ssl,
                                     const HITLS_CompressedCertificate *msg,
                                     uint8_t *out,
                                     size_t *out_len)
{
    if (ssl == NULL || msg == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }
    if (ssl->cert_compression_enabled == 0U) {
        return HITLS_CERT_COMPRESS_ERR_DISABLED;
    }
    return HITLS_DecompressCertificateMessage(msg->selected_algorithm,
                                              msg->compressed_cert_msg,
                                              msg->compressed_cert_msg_len,
                                              out,
                                              out_len,
                                              msg->uncompressed_len);
}
