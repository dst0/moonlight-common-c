// secure-desktop-stream: protocol hardening regression tests:
//  - fail-closed RTSP encryption (rtspenc:// required) and full stream encryption flags
//  - strict Transport server_port= parsing (range 1024..65535, no trailing garbage)
//  - AI_NUMERICHOST in resolveHostName (no DNS resolution)
//  - key/IV zeroing in LiStopConnection()
#include "Limelight-internal.h"
#include "Rtsp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

typedef struct _ENC_RTSP_HDR {
    uint32_t typeAndLength;
    uint32_t sequenceNumber;
    uint8_t tag[16];
} ENC_RTSP_HDR;

#define ENC_BIT 0x80000000u

typedef struct _MOCK_RTSP_CFG {
    int listenFd;
    uint16_t port;
    uint32_t encryptionSupported;
    const char* audioTransport;
    const char* videoTransport;
    const char* controlTransport;
    atomic_bool stop;
    int sawAnnounce;
    int sawPlay;
    int sawPlaintext;
} MOCK_RTSP_CFG;

static void writeBe32(uint32_t v, void* out) {
    uint8_t* p = (uint8_t*)out;
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t readBe32(const void* in) {
    const uint8_t* p = (const uint8_t*)in;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void buildRtspIv(uint32_t seq, char origin, uint8_t iv[12]) {
    memset(iv, 0, 12);
    iv[0] = (uint8_t)(seq >> 0);
    iv[1] = (uint8_t)(seq >> 8);
    iv[2] = (uint8_t)(seq >> 16);
    iv[3] = (uint8_t)(seq >> 24);
    iv[10] = (uint8_t)origin;
    iv[11] = (uint8_t)'R';
}

static void mockRtspServerThread(void* context) {
    MOCK_RTSP_CFG* cfg = (MOCK_RTSP_CFG*)context;
    PPLT_CRYPTO_CONTEXT encCtx = PltCreateCryptoContext(0);
    PPLT_CRYPTO_CONTEXT decCtx = PltCreateCryptoContext(1);
    uint32_t hostSeq = 0;

    while (!atomic_load(&cfg->stop)) {
        struct pollfd pfd;
        pfd.fd = cfg->listenFd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 25) <= 0) {
            continue;
        }
        int conn = accept(cfg->listenFd, NULL, NULL);
        if (conn < 0) {
            break;
        }

        uint8_t buf[65536];
        size_t len = 0;
        for (;;) {
            ssize_t n = recv(conn, buf + len, sizeof(buf) - len, 0);
            if (n <= 0) {
                break;
            }
            len += (size_t)n;
            if (len >= sizeof(ENC_RTSP_HDR)) {
                uint32_t tl = readBe32(buf);
                if (tl & ENC_BIT) {
                    uint32_t plen = tl & ~ENC_BIT;
                    if (len >= sizeof(ENC_RTSP_HDR) + plen) {
                        break;
                    }
                } else {
                    cfg->sawPlaintext = 1;
                    break;
                }
            }
        }

        if (len < sizeof(ENC_RTSP_HDR)) {
            close(conn);
            continue;
        }

        uint32_t tl = readBe32(buf);
        if (!(tl & ENC_BIT)) {
            cfg->sawPlaintext = 1;
            close(conn);
            continue;
        }

        uint32_t plen = tl & ~ENC_BIT;
        uint32_t seq = readBe32(buf + 4);
        uint8_t iv[12];
        buildRtspIv(seq, 'C', iv);

        char* plain = malloc(plen + 1);
        int plainLen = (int)plen;
        if (plain == NULL || !PltDecryptMessage(decCtx, ALGORITHM_AES_GCM, 0, 0, seq,
                                                (uint8_t*)StreamConfig.remoteInputAesKey,
                                                sizeof(StreamConfig.remoteInputAesKey),
                                                iv, sizeof(iv), buf + 8, 16,
                                                buf + sizeof(ENC_RTSP_HDR), (int)plen,
                                                (uint8_t*)plain, &plainLen)) {
            free(plain);
            close(conn);
            continue;
        }
        plain[plainLen] = '\0';

        char resp[2048];
        int respLen = 0;
        if (strncmp(plain, "OPTIONS ", 8) == 0) {
            respLen = snprintf(resp, sizeof(resp), "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");
        } else if (strncmp(plain, "DESCRIBE ", 9) == 0) {
            respLen = snprintf(resp, sizeof(resp),
                               "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n"
                               "sprop-parameter-sets=AAAAAU\r\n"
                               "a=x-ss-general.featureFlags:0\r\n"
                               "a=x-ss-general.encryptionSupported:%u\r\n"
                               "a=x-ss-general.encryptionRequested:0\r\n",
                               cfg->encryptionSupported);
        } else if (strncmp(plain, "SETUP streamid=audio", 20) == 0) {
            respLen = snprintf(resp, sizeof(resp),
                               "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: ABCDEF;timeout=90\r\nTransport: %s\r\n\r\n",
                               cfg->audioTransport);
        } else if (strncmp(plain, "SETUP streamid=video", 20) == 0) {
            respLen = snprintf(resp, sizeof(resp),
                               "RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: ABCDEF\r\nTransport: %s\r\n\r\n",
                               cfg->videoTransport);
        } else if (strncmp(plain, "SETUP streamid=control", 22) == 0) {
            respLen = snprintf(resp, sizeof(resp),
                               "RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: ABCDEF\r\nTransport: %s\r\n\r\n",
                               cfg->controlTransport);
        } else if (strncmp(plain, "ANNOUNCE ", 9) == 0) {
            cfg->sawAnnounce = 1;
            respLen = snprintf(resp, sizeof(resp), "RTSP/1.0 200 OK\r\nCSeq: 6\r\n\r\n");
        } else if (strncmp(plain, "PLAY ", 5) == 0) {
            cfg->sawPlay = 1;
            respLen = snprintf(resp, sizeof(resp), "RTSP/1.0 200 OK\r\nCSeq: 7\r\n\r\n");
        }
        free(plain);

        if (respLen > 0) {
            uint8_t* pkt = malloc(sizeof(ENC_RTSP_HDR) + (size_t)respLen);
            int encLen = respLen;
            hostSeq++;
            buildRtspIv(hostSeq, 'H', iv);
            writeBe32(ENC_BIT | (uint32_t)respLen, pkt);
            writeBe32(hostSeq, pkt + 4);
            if (PltEncryptMessage(encCtx, ALGORITHM_AES_GCM, 0,
                                  (uint8_t*)StreamConfig.remoteInputAesKey,
                                  sizeof(StreamConfig.remoteInputAesKey),
                                  iv, sizeof(iv), pkt + 8, 16,
                                  (uint8_t*)resp, respLen,
                                  pkt + sizeof(ENC_RTSP_HDR), &encLen)) {
                send(conn, pkt, sizeof(ENC_RTSP_HDR) + (size_t)encLen, 0);
            }
            free(pkt);
        }

        close(conn);
        if (cfg->sawPlay) {
            break;
        }
    }

    PltDestroyCryptoContext(encCtx);
    PltDestroyCryptoContext(decCtx);
}

static void initMockServer(MOCK_RTSP_CFG* cfg) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int yes = 1;

    cfg->listenFd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(cfg->listenFd >= 0);
    setsockopt(cfg->listenFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CHECK(bind(cfg->listenFd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    CHECK(listen(cfg->listenFd, 8) == 0);
    CHECK(getsockname(cfg->listenFd, (struct sockaddr*)&addr, &len) == 0);
    cfg->port = ntohs(addr.sin_port);
}

static void setupTestGlobals(uint16_t port) {
    struct sockaddr_in* sin = (struct sockaddr_in*)&RemoteAddr;

    memset(&RemoteAddr, 0, sizeof(RemoteAddr));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin->sin_port = htons(port);
    AddrLen = sizeof(struct sockaddr_in);

    AppVersionQuad[0] = 7;
    AppVersionQuad[1] = 1;
    AppVersionQuad[2] = 431;
    AppVersionQuad[3] = -1;

    RtspPortNumber = port;
    AudioPortNumber = 0;
    VideoPortNumber = 0;
    ControlPortNumber = 0;
    ConnectionInterrupted = false;

    memset(&StreamConfig, 0, sizeof(StreamConfig));
    StreamConfig.width = 1920;
    StreamConfig.height = 1080;
    StreamConfig.fps = 60;
    StreamConfig.bitrate = 20000;
    StreamConfig.packetSize = 1392;
    StreamConfig.streamingRemotely = STREAM_CFG_LOCAL;
    StreamConfig.audioConfiguration = AUDIO_CONFIGURATION_STEREO;
    StreamConfig.supportedVideoFormats = VIDEO_FORMAT_H264;
    StreamConfig.encryptionFlags = ENCFLG_ALL;
    for (int i = 0; i < 16; i++) {
        StreamConfig.remoteInputAesKey[i] = (char)(0x10 + i);
        StreamConfig.remoteInputAesIv[i] = (char)(0x20 + i);
    }
}

static void testFailClosedPlaintextRtsp(void) {
    SERVER_INFORMATION info;
    memset(&info, 0, sizeof(info));
    setupTestGlobals(48010);
    info.address = "127.0.0.1";
    info.serverInfoAppVersion = "7.1.431.-1";
    info.serverCodecModeSupport = SCM_H264;

    info.rtspSessionUrl = NULL;
    CHECK(performRtspHandshake(&info) == -1);

    info.rtspSessionUrl = "rtsp://127.0.0.1:48010";
    CHECK(performRtspHandshake(&info) == -1);

    info.rtspSessionUrl = "http://127.0.0.1:48010/rtspenc://";
    CHECK(performRtspHandshake(&info) == -1);

    // ENet cannot be used with encrypted RTSP
    AppVersionQuad[2] = 400;
    info.rtspSessionUrl = "rtspenc://127.0.0.1:48010";
    CHECK(performRtspHandshake(&info) == -1);
}

static void testFailClosedPartialStreamEncryption(void) {
    MOCK_RTSP_CFG cfg;
    PLT_THREAD thread;
    SERVER_INFORMATION info;
    char url[64];

    memset(&cfg, 0, sizeof(cfg));
    cfg.encryptionSupported = SS_ENC_CONTROL_V2 | SS_ENC_VIDEO; // missing SS_ENC_AUDIO
    cfg.audioTransport = "unicast;server_port=48000";
    cfg.videoTransport = "unicast;server_port=47998";
    cfg.controlTransport = "unicast;server_port=47999";
    initMockServer(&cfg);

    setupTestGlobals(cfg.port);
    CHECK(PltCreateThread("rtsp-mock-fail", mockRtspServerThread, &cfg, &thread) == 0);

    snprintf(url, sizeof(url), "rtspenc://127.0.0.1:%u", cfg.port);
    memset(&info, 0, sizeof(info));
    info.address = "127.0.0.1";
    info.serverInfoAppVersion = "7.1.431.-1";
    info.serverCodecModeSupport = SCM_H264;
    info.rtspSessionUrl = url;

    CHECK(performRtspHandshake(&info) != 0);
    CHECK(cfg.sawAnnounce == 0);
    CHECK(cfg.sawPlaintext == 0);

    atomic_store(&cfg.stop, true);
    PltJoinThread(&thread);
    close(cfg.listenFd);
}

static void testFullEncryptionAndTransportPorts(void) {
    MOCK_RTSP_CFG cfg;
    PLT_THREAD thread;
    SERVER_INFORMATION info;
    char url[64];

    memset(&cfg, 0, sizeof(cfg));
    cfg.encryptionSupported = SS_ENC_CONTROL_V2 | SS_ENC_VIDEO | SS_ENC_AUDIO;
    cfg.audioTransport = "unicast;server_port=80";          // invalid (< 1024) -> falls back to 48000
    cfg.videoTransport = "unicast;server_port=48100abc";    // invalid suffix -> falls back to 47998
    cfg.controlTransport = "unicast;server_port=48123;source=127.0.0.1"; // valid -> 48123
    initMockServer(&cfg);

    setupTestGlobals(cfg.port);
    CHECK(PltCreateThread("rtsp-mock-ok", mockRtspServerThread, &cfg, &thread) == 0);

    snprintf(url, sizeof(url), "rtspenc://127.0.0.1:%u", cfg.port);
    memset(&info, 0, sizeof(info));
    info.address = "127.0.0.1";
    info.serverInfoAppVersion = "7.1.431.-1";
    info.serverCodecModeSupport = SCM_H264;
    info.rtspSessionUrl = url;

    CHECK(performRtspHandshake(&info) == 0);
    CHECK(cfg.sawAnnounce == 1);
    CHECK(cfg.sawPlay == 1);
    CHECK(cfg.sawPlaintext == 0);
    CHECK(AudioPortNumber == 48000);
    CHECK(VideoPortNumber == 47998);
    CHECK(ControlPortNumber == 48123);

    atomic_store(&cfg.stop, true);
    PltJoinThread(&thread);
    close(cfg.listenFd);
}

static void testResolveHostNameNumericOnly(void) {
    struct sockaddr_storage addr;
    SOCKADDR_LEN addrLen = 0;

    CHECK(resolveHostName("localhost", AF_UNSPEC, 0, &addr, &addrLen) != 0);
    CHECK(resolveHostName("example.invalid", AF_UNSPEC, 0, &addr, &addrLen) != 0);
    CHECK(resolveHostName("127.0.0.1", AF_UNSPEC, 0, &addr, &addrLen) == 0);
    CHECK(addr.ss_family == AF_INET);
}

static void testLiStopConnectionZerosSecrets(void) {
    for (int i = 0; i < 16; i++) {
        StreamConfig.remoteInputAesKey[i] = (char)(0x41 + i);
        StreamConfig.remoteInputAesIv[i] = (char)(0x61 + i);
    }

    LiStopConnection();

    for (int i = 0; i < 16; i++) {
        CHECK(StreamConfig.remoteInputAesKey[i] == 0);
        CHECK(StreamConfig.remoteInputAesIv[i] == 0);
    }
}

int main(void) {
    PltTicksInit();

    testFailClosedPlaintextRtsp();
    testFailClosedPartialStreamEncryption();
    testFullEncryptionAndTransportPorts();
    testResolveHostNameNumericOnly();
    testLiStopConnectionZerosSecrets();

    if (failures != 0) {
        fprintf(stderr, "sds_hardening_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("sds_hardening_test: all tests passed\n");
    return 0;
}
