// secure-desktop-stream: unit tests for the microphone packet framing (src/SdsMicPacket.c).
//
// The test vectors below are shared with Sunshine's tests/unit/test_sds_mic.cpp, which must
// decrypt exactly these datagrams. They were cross-checked with the Python `cryptography`
// AESGCM implementation (see docs/DESIGN.md section 7.2 of secure-desktop-stream).
//
// Build and run: tests/run-sds-mic-test.sh (or the moonlight-common-c-sds-mic-test CMake target
// with -DMOONLIGHT_COMMON_C_BUILD_SDS_TESTS=ON).
#include "SdsMic.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static const unsigned char kKey[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Vector 1: first packet of a stream, a 3-byte Opus frame (20 ms CELT silence).
static const unsigned char kVector1Opus[] = { 0xf8, 0xff, 0xfe };
static const unsigned char kVector1Datagram[] = {
    // header: version 1, flags 0, reserved 0, sequence 0, timestamp 0
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // tag
    0x1c, 0x34, 0x27, 0xe5, 0x61, 0xcd, 0x56, 0xa1, 0x23, 0xba, 0x6e, 0x51, 0x4a, 0x2d, 0x15, 0xb1,
    // ciphertext
    0xa8, 0x93, 0xdc,
};

// Vector 2: sequence 0x01020304 (checks the little-endian IV), timestamp 0x0a0b0c0d,
// 32 payload bytes 0x00..0x1f.
static const unsigned char kVector2Datagram[] = {
    0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
    0x4c, 0x18, 0x08, 0x03, 0xf5, 0x66, 0xcf, 0x29, 0xcc, 0xb2, 0xa8, 0x3d, 0x0c, 0xb0, 0xeb, 0xbc,
    0xda, 0xc1, 0xcd, 0x4d, 0xf2, 0x3f, 0x80, 0x1c, 0x45, 0x08, 0x46, 0x59, 0x30, 0x9a, 0xac, 0xa9,
    0xa2, 0x2a, 0x06, 0x8c, 0xc4, 0xfb, 0xb0, 0x5f, 0xcd, 0x6a, 0xd7, 0xb7, 0x55, 0xf0, 0x2d, 0x20,
};

static void dumpHex(const char* name, const unsigned char* data, int length) {
    fprintf(stderr, "%s (%d):", name, length);
    for (int i = 0; i < length; i++) {
        fprintf(stderr, "%s%02x", (i % 16) == 0 ? "\n  " : " ", data[i]);
    }
    fprintf(stderr, "\n");
}

// Independent decryption with raw OpenSSL EVP calls, constructing IV and AAD by hand
// from the DESIGN.md description rather than via the helpers under test.
static int referenceDecrypt(const unsigned char* datagram, int length, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12] = { 0 };
    int outLength = 0;
    int finalLength = 0;
    int ok;

    if (length < 12 + 16) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // sequence is big-endian on the wire and little-endian in the IV
    iv[0] = datagram[7];
    iv[1] = datagram[6];
    iv[2] = datagram[5];
    iv[3] = datagram[4];
    iv[10] = 'C';
    iv[11] = 'M';

    ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
         EVP_DecryptInit_ex(ctx, NULL, NULL, kKey, iv) == 1 &&
         EVP_DecryptUpdate(ctx, NULL, &outLength, datagram, 12) == 1 &&
         EVP_DecryptUpdate(ctx, plaintext, &outLength, datagram + 28, length - 28) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(datagram + 12)) == 1 &&
         EVP_DecryptFinal_ex(ctx, plaintext + outLength, &finalLength) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outLength + finalLength : -1;
}

static void testIvLayout(void) {
    unsigned char iv[SDS_MIC_IV_SIZE];
    static const unsigned char expected[SDS_MIC_IV_SIZE] = {
        0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0, 0, 0, 'C', 'M'
    };

    memset(iv, 0xaa, sizeof(iv));
    sdsMicBuildIv(0x01020304, iv);
    CHECK(memcmp(iv, expected, sizeof(iv)) == 0);
}

static void testHeaderLayout(void) {
    unsigned char header[SDS_MIC_HEADER_SIZE];
    static const unsigned char expected[SDS_MIC_HEADER_SIZE] = {
        0x01, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04
    };

    sdsMicBuildHeader(0xdeadbeef, 0x01020304, header);
    CHECK(memcmp(header, expected, sizeof(header)) == 0);
}

static void testVectors(void) {
    unsigned char out[SDS_MIC_MAX_DATAGRAM];
    unsigned char opus2[32];
    PPLT_CRYPTO_CONTEXT ctx = PltCreateCryptoContext(0);
    int len;

    for (int i = 0; i < 32; i++) {
        opus2[i] = (unsigned char)i;
    }

    len = sdsMicEncryptPacket(ctx, kKey, 0, 0, kVector1Opus, sizeof(kVector1Opus), out, sizeof(out));
    CHECK(len == (int)sizeof(kVector1Datagram));
    if (len != (int)sizeof(kVector1Datagram) || memcmp(out, kVector1Datagram, sizeof(kVector1Datagram)) != 0) {
        dumpHex("vector1", out, len);
        failures++;
    }

    // Same context, new IV: the context must re-key the IV per packet
    len = sdsMicEncryptPacket(ctx, kKey, 0x01020304, 0x0a0b0c0d, opus2, sizeof(opus2), out, sizeof(out));
    CHECK(len == (int)sizeof(kVector2Datagram));
    if (len != (int)sizeof(kVector2Datagram) || memcmp(out, kVector2Datagram, sizeof(kVector2Datagram)) != 0) {
        dumpHex("vector2", out, len);
        failures++;
    }

    PltDestroyCryptoContext(ctx);
}

static void testReferenceDecryptAndTamper(void) {
    unsigned char plain[SDS_MIC_MAX_DATAGRAM];
    unsigned char copy[sizeof(kVector2Datagram)];
    int len;

    len = referenceDecrypt(kVector1Datagram, sizeof(kVector1Datagram), plain);
    CHECK(len == (int)sizeof(kVector1Opus));
    CHECK(len > 0 && memcmp(plain, kVector1Opus, sizeof(kVector1Opus)) == 0);

    len = referenceDecrypt(kVector2Datagram, sizeof(kVector2Datagram), plain);
    CHECK(len == 32);
    for (int i = 0; i < 32 && len == 32; i++) {
        CHECK(plain[i] == i);
    }

    // Every single-bit flip in the header (AAD), tag or ciphertext must fail authentication
    for (size_t byte = 0; byte < sizeof(copy); byte++) {
        memcpy(copy, kVector2Datagram, sizeof(copy));
        copy[byte] ^= 0x01;
        CHECK(referenceDecrypt(copy, sizeof(copy), plain) < 0);
    }
}

static void testInvalidArguments(void) {
    unsigned char out[SDS_MIC_MAX_DATAGRAM + 64];
    unsigned char big[SDS_MIC_MAX_OPUS_LENGTH + 1];
    PPLT_CRYPTO_CONTEXT ctx = PltCreateCryptoContext(0);

    memset(big, 0x55, sizeof(big));

    CHECK(sdsMicEncryptPacket(NULL, kKey, 0, 0, kVector1Opus, 3, out, sizeof(out)) == -1);
    CHECK(sdsMicEncryptPacket(ctx, NULL, 0, 0, kVector1Opus, 3, out, sizeof(out)) == -1);
    CHECK(sdsMicEncryptPacket(ctx, kKey, 0, 0, NULL, 3, out, sizeof(out)) == -1);
    CHECK(sdsMicEncryptPacket(ctx, kKey, 0, 0, kVector1Opus, 0, out, sizeof(out)) == -1);
    CHECK(sdsMicEncryptPacket(ctx, kKey, 0, 0, kVector1Opus, -1, out, sizeof(out)) == -1);
    CHECK(sdsMicEncryptPacket(ctx, kKey, 0, 0, kVector1Opus, 3, out, 12 + 16 + 2) == -1);
    CHECK(sdsMicEncryptPacket(ctx, kKey, 0, 0, big, sizeof(big), out, sizeof(out)) == -1);

    // Largest allowed frame produces exactly the 1400-byte maximum datagram
    CHECK(sdsMicEncryptPacket(ctx, kKey, 7, 960 * 7, big, SDS_MIC_MAX_OPUS_LENGTH, out, sizeof(out)) == SDS_MIC_MAX_DATAGRAM);

    // PltEncryptMessageAead rejects invalid keyLength and ivLength
    {
        unsigned char iv[12] = { 0 };
        unsigned char tag[16] = { 0 };
        unsigned char badKey[32] = { 0 };
        int outLen = 0;
        CHECK(!PltEncryptMessageAead(ctx, badKey, 0, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), kVector1Opus, sizeof(kVector1Opus), out, &outLen));
        CHECK(!PltEncryptMessageAead(ctx, badKey, 15, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), kVector1Opus, sizeof(kVector1Opus), out, &outLen));
        CHECK(!PltEncryptMessageAead(ctx, badKey, 32, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), kVector1Opus, sizeof(kVector1Opus), out, &outLen));
        CHECK(!PltEncryptMessageAead(ctx, (unsigned char*)kKey, 16, iv, 0, NULL, 0, tag, sizeof(tag), kVector1Opus, sizeof(kVector1Opus), out, &outLen));
        CHECK(!PltEncryptMessageAead(ctx, (unsigned char*)kKey, 16, iv, -1, NULL, 0, tag, sizeof(tag), kVector1Opus, sizeof(kVector1Opus), out, &outLen));
    }

    PltDestroyCryptoContext(ctx);
}

static void testTimestamps(void) {
    CHECK(sdsMicNextTimestamp(12345, true, 999) == 0);
    CHECK(sdsMicNextTimestamp(0, false, 20) == 960);
    CHECK(sdsMicNextTimestamp(960, false, 0) == 1920);
    CHECK(sdsMicNextTimestamp(960, false, SDS_MIC_PAUSE_THRESHOLD_MS) == 1920);
    // 1 s pause -> 50 frames
    CHECK(sdsMicNextTimestamp(960, false, 1000) == 960 + 48000);
    // 130 ms pause -> rounded down to 6 whole frames
    CHECK(sdsMicNextTimestamp(0, false, 130) == 6 * 960);
    // 32-bit wrap is modular
    CHECK(sdsMicNextTimestamp(0xFFFFFFFFu - 959, false, 20) == 0);
}

int main(void) {
    testIvLayout();
    testHeaderLayout();
    testVectors();
    testReferenceDecryptAndTamper();
    testInvalidArguments();
    testTimestamps();

    if (failures != 0) {
        fprintf(stderr, "sds_mic_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("sds_mic_test: all tests passed\n");
    return 0;
}
