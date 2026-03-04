#ifndef HITLS_CERT_COMPRESS_H
#define HITLS_CERT_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 8879 Certificate Compression Algorithms */
#define HITLS_EXT_CERTIFICATE_COMPRESSION 27U

#define HITLS_CERT_COMPRESS_ZLIB   1U
#define HITLS_CERT_COMPRESS_BROTLI 2U
#define HITLS_CERT_COMPRESS_ZSTD   3U

#define HITLS_CERT_COMPRESS_MAX_UNCOMPRESSED_LEN (16U * 1024U * 1024U)
#define HITLS_CERT_COMPRESS_DEFAULT_THRESHOLD 1024U

typedef enum {
    HITLS_CERT_COMPRESS_MODE_NONE = 0,
    HITLS_CERT_COMPRESS_MODE_CLIENT_ADVERTISE,
    HITLS_CERT_COMPRESS_MODE_SERVER_SELECT,
} HITLS_CertCompressMode;

typedef enum {
    HITLS_CERT_COMPRESS_OK = 0,
    HITLS_CERT_COMPRESS_ERR_NOT_FOUND = -1,
    HITLS_CERT_COMPRESS_ERR_INVALID_ARG = -2,
    HITLS_CERT_COMPRESS_ERR_BUFFER_SMALL = -3,
    HITLS_CERT_COMPRESS_ERR_DECODE = -4,
    HITLS_CERT_COMPRESS_ERR_ENCODE = -5,
    HITLS_CERT_COMPRESS_ERR_DISABLED = -6,
    HITLS_CERT_COMPRESS_ERR_NO_COMMON_ALGO = -7,
    HITLS_CERT_COMPRESS_ERR_LIMIT = -8,
} HITLS_CertCompressResult;

typedef struct {
    uint16_t algorithm;
    uint8_t enabled;
} HITLS_CertCompressAlgoConfig;

typedef struct {
    uint16_t algorithm;
    const char *name;
    int (*compress)(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
    int (*decompress)(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
} HITLS_CertCompressMethod;

typedef struct {
    HITLS_CertCompressAlgoConfig algos[8];
    size_t algo_count;
    HITLS_CertCompressAlgoConfig peer_algos[8];
    size_t peer_algo_count;
    uint16_t selected_algorithm;
    uint8_t send_compressed_by_default;
    uint32_t min_compress_len;
    uint32_t last_uncompressed_len;
    uint32_t last_compressed_len;
} HITLS_CertCompressCtx;

typedef struct {
    uint16_t selected_algorithm;
    uint32_t uncompressed_len;
    const uint8_t *compressed_cert_msg;
    size_t compressed_cert_msg_len;
} HITLS_CompressedCertificate;

void HITLS_CertCompressCtxInit(HITLS_CertCompressCtx *ctx);
int HITLS_CertCompressEnable(HITLS_CertCompressCtx *ctx, uint16_t algorithm, uint8_t enabled);
int HITLS_CertCompressIsEnabled(const HITLS_CertCompressCtx *ctx, uint16_t algorithm);

int HITLS_RegisterDefaultCertCompressionMethods(void);
int HITLS_RegisterCertCompression(const HITLS_CertCompressMethod *method);
const HITLS_CertCompressMethod *HITLS_GetCertCompression(uint16_t algorithm);

int HITLS_ParseCompressCertificateExtension(HITLS_CertCompressCtx *ctx,
                                            const uint8_t *ext_data,
                                            size_t ext_len);
int HITLS_BuildCompressCertificateExtension(const HITLS_CertCompressCtx *ctx,
                                            uint8_t *out,
                                            size_t *out_len);

int HITLS_SelectCommonCertCompression(HITLS_CertCompressCtx *ctx,
                                      const uint16_t *server_priority,
                                      size_t server_priority_len,
                                      uint16_t *selected_algorithm);
int HITLS_ShouldSendCompressedCertificate(const HITLS_CertCompressCtx *ctx,
                                          size_t cert_msg_len);

int HITLS_CompressCertificateMessage(const HITLS_CertCompressCtx *ctx,
                                     uint16_t algorithm,
                                     const uint8_t *cert_msg,
                                     size_t cert_msg_len,
                                     uint8_t *out,
                                     size_t *out_len,
                                     uint32_t *uncompressed_len);

int HITLS_DecompressCertificateMessage(uint16_t algorithm,
                                       const uint8_t *compressed,
                                       size_t compressed_len,
                                       uint8_t *out,
                                       size_t *out_len,
                                       uint32_t expected_uncompressed_len);

int HITLS_BuildCompressedCertificateHandshake(uint16_t algorithm,
                                              uint32_t uncompressed_len,
                                              const uint8_t *compressed,
                                              size_t compressed_len,
                                              uint8_t *out,
                                              size_t *out_len);

int HITLS_ParseCompressedCertificateHandshake(const uint8_t *in,
                                              size_t in_len,
                                              HITLS_CompressedCertificate *msg);

#ifdef __cplusplus
}
#endif

#endif
