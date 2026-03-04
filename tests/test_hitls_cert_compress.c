#include "hitls_cert_compress.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void TestExtensionAndSelection(void)
{
    HITLS_CertCompressCtx server_ctx;
    uint8_t ext_data[8];
    uint16_t selected = 0;
    uint16_t priority[] = {HITLS_CERT_COMPRESS_ZSTD, HITLS_CERT_COMPRESS_BROTLI, HITLS_CERT_COMPRESS_ZLIB};

    HITLS_CertCompressCtxInit(&server_ctx);
    assert(HITLS_CertCompressEnable(&server_ctx, HITLS_CERT_COMPRESS_ZSTD, 1) == HITLS_CERT_COMPRESS_OK);
    assert(HITLS_CertCompressEnable(&server_ctx, HITLS_CERT_COMPRESS_ZLIB, 1) == HITLS_CERT_COMPRESS_OK);

    /* client advertises zlib then brotli */
    ext_data[0] = 0;
    ext_data[1] = HITLS_CERT_COMPRESS_ZLIB;
    ext_data[2] = 0;
    ext_data[3] = HITLS_CERT_COMPRESS_BROTLI;

    assert(HITLS_ParseCompressCertificateExtension(&server_ctx, ext_data, 4) == HITLS_CERT_COMPRESS_OK);
    assert(HITLS_SelectCommonCertCompression(&server_ctx, priority, 3, &selected) == HITLS_CERT_COMPRESS_OK);
    assert(selected == HITLS_CERT_COMPRESS_ZLIB);
}

static void TestCompressAndHandshake(void)
{
    HITLS_CertCompressCtx ctx;
    const char *plain = "AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDD";
    uint8_t compressed[256];
    uint8_t decompressed[256];
    uint8_t handshake[300];
    size_t compressed_len = sizeof(compressed);
    size_t decompressed_len = sizeof(decompressed);
    size_t handshake_len = sizeof(handshake);
    uint32_t plain_len = 0;
    HITLS_CompressedCertificate parsed;

    HITLS_CertCompressCtxInit(&ctx);
    ctx.send_compressed_by_default = 1;
    ctx.selected_algorithm = HITLS_CERT_COMPRESS_ZLIB;
    ctx.min_compress_len = 8;

    assert(HITLS_RegisterDefaultCertCompressionMethods() == HITLS_CERT_COMPRESS_OK);
    assert(HITLS_CertCompressEnable(&ctx, HITLS_CERT_COMPRESS_ZLIB, 1) == HITLS_CERT_COMPRESS_OK);
    assert(HITLS_ShouldSendCompressedCertificate(&ctx, strlen(plain)) == 1);

    assert(HITLS_CompressCertificateMessage(&ctx,
                                            HITLS_CERT_COMPRESS_ZLIB,
                                            (const uint8_t *)plain,
                                            strlen(plain),
                                            compressed,
                                            &compressed_len,
                                            &plain_len) == HITLS_CERT_COMPRESS_OK);
    assert(plain_len == strlen(plain));

    assert(HITLS_BuildCompressedCertificateHandshake(HITLS_CERT_COMPRESS_ZLIB,
                                                     plain_len,
                                                     compressed,
                                                     compressed_len,
                                                     handshake,
                                                     &handshake_len) == HITLS_CERT_COMPRESS_OK);

    assert(HITLS_ParseCompressedCertificateHandshake(handshake, handshake_len, &parsed) == HITLS_CERT_COMPRESS_OK);
    assert(parsed.selected_algorithm == HITLS_CERT_COMPRESS_ZLIB);

    assert(HITLS_DecompressCertificateMessage(parsed.selected_algorithm,
                                              parsed.compressed_cert_msg,
                                              parsed.compressed_cert_msg_len,
                                              decompressed,
                                              &decompressed_len,
                                              parsed.uncompressed_len) == HITLS_CERT_COMPRESS_OK);
    assert(decompressed_len == strlen(plain));
    assert(memcmp(decompressed, plain, strlen(plain)) == 0);
}


static void TestNegativeCases(void)
{
    HITLS_CertCompressCtx ctx;
    uint8_t bad_ext[3] = {0x00, 0x01, 0x00};
    uint8_t out[8] = {0};
    size_t out_len = sizeof(out);

    HITLS_CertCompressCtxInit(&ctx);
    assert(HITLS_ParseCompressCertificateExtension(&ctx, bad_ext, sizeof(bad_ext)) == HITLS_CERT_COMPRESS_ERR_INVALID_ARG);

    assert(HITLS_CertCompressEnable(&ctx, HITLS_CERT_COMPRESS_ZLIB, 1) == HITLS_CERT_COMPRESS_OK);
    assert(HITLS_BuildCompressCertificateExtension(&ctx, out, &out_len) == HITLS_CERT_COMPRESS_OK);

    {
        uint8_t compressed[2] = {1, 2};
        uint8_t out_buf[8] = {0};
        size_t out_len_local = sizeof(out_buf);
        assert(HITLS_DecompressCertificateMessage(HITLS_CERT_COMPRESS_ZLIB,
                                                  compressed,
                                                  sizeof(compressed),
                                                  out_buf,
                                                  &out_len_local,
                                                  HITLS_CERT_COMPRESS_MAX_UNCOMPRESSED_LEN + 1U) == HITLS_CERT_COMPRESS_ERR_LIMIT);
    }
}

int main(void)
{
    TestExtensionAndSelection();
    TestCompressAndHandshake();
    TestNegativeCases();
    puts("test_hitls_cert_compress: PASS");
    return 0;
}
