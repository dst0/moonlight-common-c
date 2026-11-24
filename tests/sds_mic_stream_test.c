// secure-desktop-stream: lifecycle tests for the microphone stream (src/SdsMicStream.c):
// ping binding packets, LiSendMicrophoneOpusData() framing over a real loopback UDP socket,
// drop-when-not-connected behaviour and concurrent stop while senders are active.
//
// Build and run: tests/run-sds-mic-test.sh
#include "SdsMic.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/time.h>
#endif

// Globals normally defined in Connection.c
char* RemoteAddrString;
struct sockaddr_storage RemoteAddr;
struct sockaddr_storage LocalAddr;
SOCKADDR_LEN AddrLen;
STREAM_CONFIGURATION StreamConfig;
CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;

// Platform.c references ENet for initializePlatform(), which this test does not use
int enet_initialize(void) { return 0; }
void enet_deinitialize(void) {}

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
static const char kPingPayload[16] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P' };

static SOCKET receiver = INVALID_SOCKET;

static void logMessage(const char* format, ...) {
    (void)format;
}

static int referenceDecrypt(const unsigned char* datagram, int length, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12] = { 0 };
    int outLength = 0;
    int finalLength = 0;
    int ok;

    iv[0] = datagram[7];
    iv[1] = datagram[6];
    iv[2] = datagram[5];
    iv[3] = datagram[4];
    iv[10] = 'C';
    iv[11] = 'M';

    ok = length >= 28 &&
         EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
         EVP_DecryptInit_ex(ctx, NULL, NULL, kKey, iv) == 1 &&
         EVP_DecryptUpdate(ctx, NULL, &outLength, datagram, 12) == 1 &&
         EVP_DecryptUpdate(ctx, plaintext, &outLength, datagram + 28, length - 28) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(datagram + 12)) == 1 &&
         EVP_DecryptFinal_ex(ctx, plaintext + outLength, &finalLength) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outLength + finalLength : -1;
}

// Receives one datagram, waiting at most timeoutMs. Returns its length or -1 on timeout.
static int receiveDatagram(unsigned char* buffer, int capacity, int timeoutMs) {
    struct timeval tv;
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(receiver, &fds);
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    if (select((int)receiver + 1, &fds, NULL, NULL, &tv) <= 0) {
        return -1;
    }

    return (int)recv(receiver, (char*)buffer, capacity, 0);
}

// Receives the next non-ping datagram (pings are exactly sizeof(SS_PING) bytes)
static int receiveMicPacket(unsigned char* buffer, int capacity, int timeoutMs) {
    for (;;) {
        int len = receiveDatagram(buffer, capacity, timeoutMs);
        if (len != (int)sizeof(SS_PING)) {
            return len;
        }
    }
}

static uint32_t readBe32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t setUpLoopback(void) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    receiver = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(receiver, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
            getsockname(receiver, (struct sockaddr*)&addr, &len) != 0) {
        fprintf(stderr, "cannot bind loopback receiver\n");
        exit(2);
    }

    memset(&RemoteAddr, 0, sizeof(RemoteAddr));
    memcpy(&RemoteAddr, &addr, sizeof(addr));
    ((struct sockaddr_in*)&RemoteAddr)->sin_port = 0;
    memset(&LocalAddr, 0, sizeof(LocalAddr));
    AddrLen = sizeof(struct sockaddr_in);
    memcpy(StreamConfig.remoteInputAesKey, kKey, sizeof(kKey));

    return ntohs(addr.sin_port);
}

static void negotiate(uint16_t port) {
    initializeMicStream();
    MicPortNumber = port;
    memcpy(MicPingPayload.payload, kPingPayload, sizeof(kPingPayload));
    MicStreamNegotiated = true;
}

static void testDropsWhenNotConnected(void) {
    static const unsigned char frame[] = { 0xf8, 0xff, 0xfe };

    initializeMicStream();
    CHECK(!LiIsMicrophoneStreamActive());
    CHECK(LiSendMicrophoneOpusData(frame, sizeof(frame)) == LI_ERR_UNSUPPORTED);

    // Not negotiated: start is a successful no-op
    CHECK(startMicStream() == 0);
    CHECK(!LiIsMicrophoneStreamActive());
    CHECK(LiSendMicrophoneOpusData(frame, sizeof(frame)) == LI_ERR_UNSUPPORTED);

    // Stop without start is safe (also called on early connection failures)
    stopMicStream();
    stopMicStream();
}

static void testPingAndFraming(uint16_t port) {
    unsigned char buffer[2048];
    unsigned char plain[2048];
    unsigned char frame[100];
    int len;

    negotiate(port);
    CHECK(startMicStream() == 0);
    CHECK(LiIsMicrophoneStreamActive());

    // The first ping goes out immediately, the second about 500 ms later
    len = receiveDatagram(buffer, sizeof(buffer), 1000);
    CHECK(len == (int)sizeof(SS_PING));
    CHECK(len > 0 && memcmp(buffer, kPingPayload, sizeof(kPingPayload)) == 0);
    CHECK(len > 0 && readBe32(&buffer[16]) == 1);
    len = receiveDatagram(buffer, sizeof(buffer), 1500);
    CHECK(len == (int)sizeof(SS_PING));
    CHECK(len > 0 && readBe32(&buffer[16]) == 2);

    for (int i = 0; i < (int)sizeof(frame); i++) {
        frame[i] = (unsigned char)(i * 7);
    }

    for (uint32_t seq = 0; seq < 3; seq++) {
        frame[0] = (unsigned char)seq;
        CHECK(LiSendMicrophoneOpusData(frame, sizeof(frame)) == 0);

        len = receiveMicPacket(buffer, sizeof(buffer), 1000);
        CHECK(len == SDS_MIC_HEADER_SIZE + SDS_MIC_TAG_SIZE + (int)sizeof(frame));
        if (len <= 0) {
            continue;
        }
        CHECK(buffer[0] == SDS_MIC_VERSION);
        CHECK(buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 0);
        CHECK(readBe32(&buffer[4]) == seq);
        CHECK(readBe32(&buffer[8]) == seq * SDS_MIC_FRAME_SAMPLES);
        CHECK(referenceDecrypt(buffer, len, plain) == (int)sizeof(frame));
        CHECK(memcmp(plain, frame, sizeof(frame)) == 0);
    }

    // A pause longer than the threshold advances the timestamp by wall-clock time
    PltSleepMs(300);
    CHECK(LiSendMicrophoneOpusData(frame, sizeof(frame)) == 0);
    len = receiveMicPacket(buffer, sizeof(buffer), 1000);
    CHECK(len > 0 && readBe32(&buffer[4]) == 3);
    CHECK(len > 0 && readBe32(&buffer[8]) >= 2 * SDS_MIC_FRAME_SAMPLES + 14 * SDS_MIC_FRAME_SAMPLES);

    // Invalid frames are rejected without consuming a sequence number
    CHECK(LiSendMicrophoneOpusData(NULL, 10) < 0);
    CHECK(LiSendMicrophoneOpusData(frame, 0) < 0);
    {
        static unsigned char big[SDS_MIC_MAX_OPUS_LENGTH + 1];
        CHECK(LiSendMicrophoneOpusData(big, sizeof(big)) < 0);
        CHECK(LiSendMicrophoneOpusData(big, SDS_MIC_MAX_OPUS_LENGTH) == 0);
        len = receiveMicPacket(buffer, sizeof(buffer), 1000);
        CHECK(len == SDS_MIC_MAX_DATAGRAM);
        CHECK(len > 0 && readBe32(&buffer[4]) == 4);
    }

    stopMicStream();
    CHECK(!LiIsMicrophoneStreamActive());
    CHECK(!MicStreamNegotiated);
    CHECK(MicPortNumber == 0);
    CHECK(LiSendMicrophoneOpusData(frame, sizeof(frame)) == LI_ERR_UNSUPPORTED);

    // Nothing but at most one in-flight ping may arrive after stop
    while (receiveDatagram(buffer, sizeof(buffer), 200) > 0) {
    }
    CHECK(receiveDatagram(buffer, sizeof(buffer), 700) < 0);
}

static PLT_THREAD senderThreads[4];
static atomic_int sendsAfterStop;
static atomic_bool stopRequested;

static void senderProc(void* context) {
    static const unsigned char frame[] = { 0xf8, 0xff, 0xfe };
    (void)context;

    while (!PltIsThreadInterrupted((PLT_THREAD*)context)) {
        bool stopped = atomic_load(&stopRequested);
        int ret = LiSendMicrophoneOpusData(frame, sizeof(frame));
        if (stopped && ret == 0) {
            // A send that started after stop completed must never succeed
            atomic_fetch_add(&sendsAfterStop, 1);
        }
    }
}

static void testConcurrentStop(uint16_t port) {
    unsigned char buffer[2048];

    for (int round = 0; round < 20; round++) {
        negotiate(port);
        CHECK(startMicStream() == 0);
        atomic_store(&stopRequested, false);

        for (int i = 0; i < 4; i++) {
            CHECK(PltCreateThread("sender", senderProc, &senderThreads[i], &senderThreads[i]) == 0);
        }
        PltSleepMs(5);
        stopMicStream();
        atomic_store(&stopRequested, true);
        PltSleepMs(5);
        for (int i = 0; i < 4; i++) {
            PltInterruptThread(&senderThreads[i]);
            PltJoinThread(&senderThreads[i]);
        }

        while (receiveDatagram(buffer, sizeof(buffer), 0) > 0) {
        }
    }

    CHECK(atomic_load(&sendsAfterStop) == 0);
}

int main(void) {
    uint16_t port;

    ListenerCallbacks.logMessage = logMessage;
    PltTicksInit();
    port = setUpLoopback();

    testDropsWhenNotConnected();
    testPingAndFraming(port);
    testConcurrentStop(port);

    closeSocket(receiver);

    if (failures != 0) {
        fprintf(stderr, "sds_mic_stream_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("sds_mic_stream_test: all tests passed\n");
    return 0;
}
