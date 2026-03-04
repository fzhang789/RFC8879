#include "hitls_cert_compress.h"

#include <string.h>

#define HITLS_MAX_REGISTERED_METHODS 8

static HITLS_CertCompressMethod g_methods[HITLS_MAX_REGISTERED_METHODS];
static size_t g_method_count = 0;

void HITLS_CertCompressCtxInit(HITLS_CertCompressCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
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
    if (ctx == NULL || ext_data == NULL || (ext_len % 2U) != 0U) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    HITLS_CertCompressCtxInit(ctx);
    for (i = 0; i + 1 < ext_len; i += 2) {
        uint16_t algo = (uint16_t)((ext_data[i] << 8) | ext_data[i + 1]);
        int rc = HITLS_CertCompressEnable(ctx, algo, 1);
        if (rc != HITLS_CERT_COMPRESS_OK) {
            return rc;
        }
    }

    return HITLS_CERT_COMPRESS_OK;
}

int HITLS_BuildCompressCertificateExtension(const HITLS_CertCompressCtx *ctx,
                                            uint8_t *out,
                                            size_t *out_len)
{
    size_t i;
    size_t required;

    if (ctx == NULL || out_len == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    required = ctx->algo_count * 2U;
    if (out == NULL || *out_len < required) {
        *out_len = required;
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    for (i = 0; i < ctx->algo_count; i++) {
        out[2 * i] = (uint8_t)(ctx->algos[i].algorithm >> 8);
        out[2 * i + 1] = (uint8_t)(ctx->algos[i].algorithm & 0xFFU);
    }

    *out_len = required;
    return HITLS_CERT_COMPRESS_OK;
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
