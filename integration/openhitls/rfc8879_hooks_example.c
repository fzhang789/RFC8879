/*
 * Example upstream hooks for integrating RFC8879 in openHiTLS.
 *
 * This file is a migration template and is intentionally not compiled by this PoC repo.
 * Replace placeholder openHiTLS types/functions with real project symbols.
 */

#include "hitls_cert_compress.h"

/* Placeholder project types used as migration examples. */
typedef struct {
    HITLS_SSL *cert_comp;
} OHTLS_Handshake;

typedef struct {
    OHTLS_Handshake hs;
} OHTLS_SSL;

/* Example: parse ClientHello compress_certificate extension on server side. */
int OHTLS_OnClientHelloCertCompressExt(OHTLS_SSL *ssl, const uint8_t *ext_data, size_t ext_len)
{
    if (ssl == NULL || ssl->hs.cert_comp == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    return HITLS_SSL_parse_peer_cert_compress_ext(ssl->hs.cert_comp, ext_data, ext_len);
}

/* Example: select algorithm based on server priority. */
int OHTLS_ServerSelectCertCompression(OHTLS_SSL *ssl)
{
    static const uint16_t kServerPriority[] = {
        HITLS_CERT_COMPRESS_ZSTD,
        HITLS_CERT_COMPRESS_BROTLI,
        HITLS_CERT_COMPRESS_ZLIB,
    };

    if (ssl == NULL || ssl->hs.cert_comp == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    return HITLS_SSL_negotiate_cert_compression(ssl->hs.cert_comp,
                                                 kServerPriority,
                                                 sizeof(kServerPriority) / sizeof(kServerPriority[0]));
}

/* Example: send Certificate or CompressedCertificate according to negotiation. */
int OHTLS_BuildCertificateFlight(OHTLS_SSL *ssl,
                                 const uint8_t *cert_msg,
                                 size_t cert_msg_len,
                                 uint8_t *out,
                                 size_t *out_len)
{
    uint8_t compressed[64 * 1024];
    size_t compressed_len = sizeof(compressed);
    uint32_t uncompressed_len = 0;

    if (ssl == NULL || ssl->hs.cert_comp == NULL || cert_msg == NULL || out == NULL || out_len == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    if (HITLS_SSL_compress_certificate(ssl->hs.cert_comp,
                                       cert_msg,
                                       cert_msg_len,
                                       compressed,
                                       &compressed_len,
                                       &uncompressed_len) == HITLS_CERT_COMPRESS_OK) {
        return HITLS_BuildCompressedCertificateHandshake(
            ssl->hs.cert_comp->cert_compress.selected_algorithm,
            uncompressed_len,
            compressed,
            compressed_len,
            out,
            out_len);
    }

    /* Fallback path: send plain Certificate message. */
    if (*out_len < cert_msg_len) {
        *out_len = cert_msg_len;
        return HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL;
    }

    for (size_t i = 0; i < cert_msg_len; i++) {
        out[i] = cert_msg[i];
    }
    *out_len = cert_msg_len;
    return HITLS_CERT_COMPRESS_OK;
}

/* Example: parse incoming CompressedCertificate on receive path. */
int OHTLS_ParseCompressedCertificate(OHTLS_SSL *ssl,
                                     const uint8_t *in,
                                     size_t in_len,
                                     uint8_t *plain_out,
                                     size_t *plain_out_len)
{
    HITLS_CompressedCertificate msg;
    int rc;

    if (ssl == NULL || ssl->hs.cert_comp == NULL || in == NULL) {
        return HITLS_CERT_COMPRESS_ERR_INVALID_ARG;
    }

    rc = HITLS_ParseCompressedCertificateHandshake(in, in_len, &msg);
    if (rc != HITLS_CERT_COMPRESS_OK) {
        return rc;
    }

    return HITLS_SSL_decompress_certificate(ssl->hs.cert_comp, &msg, plain_out, plain_out_len);
}
