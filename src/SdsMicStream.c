// secure-desktop-stream: microphone stream lifecycle and LiSendMicrophoneOpusData()
#include "SdsMic.h"

// Negotiated by RtspConnection.c
uint16_t MicPortNumber;
SS_PING MicPingPayload;
bool MicStreamNegotiated;

static SOCKET micSocket = INVALID_SOCKET;
static PLT_THREAD micPingThread;
static bool micPingThreadStarted;
static PLT_MUTEX micSendLock;
static bool micSendLockCreated;
static PPLT_CRYPTO_CONTEXT micCryptoCtx;
static LC_SOCKADDR micTargetAddr;

static uint32_t micNextSequence;
static uint32_t micLastTimestamp;
static uint64_t micLastSendMs;
static bool micSequenceExhausted;

// Senders increment micSendersInFlight before checking micStreamRunning; stopMicStream()
// clears micStreamRunning and then waits for micSendersInFlight to drain. With sequentially
// consistent atomics this guarantees no sender touches the socket, lock or crypto context
// after stopMicStream() starts tearing them down.
static atomic_bool micStreamRunning;
static atomic_int micSendersInFlight;
static atomic_bool micSentData;

static void sdsMicPingThreadProc(void* context) {
    uint32_t pingCount = 0;
    uint32_t sinceLastPingMs = SDS_MIC_PING_FAST_MS;

    (void)context;

    while (!PltIsThreadInterrupted(&micPingThread)) {
        uint32_t interval = atomic_load(&micSentData) ? SDS_MIC_PING_SLOW_MS : SDS_MIC_PING_FAST_MS;

        if (sinceLastPingMs >= interval) {
            SS_PING ping;

            memcpy(&ping, &MicPingPayload, sizeof(ping));
            pingCount++;
            ping.sequenceNumber = BE32(pingCount);

            // Errors (e.g. ICMP port unreachable before the host binds) are ignored;
            // the next ping retries.
            sendto(micSocket, (char*)&ping, sizeof(ping), 0, (struct sockaddr*)&micTargetAddr, AddrLen);
            sinceLastPingMs = 0;
        }

        PltSleepMsInterruptible(&micPingThread, SDS_MIC_PING_FAST_MS);
        sinceLastPingMs += SDS_MIC_PING_FAST_MS;
    }
}

void initializeMicStream(void) {
    MicPortNumber = 0;
    memset(&MicPingPayload, 0, sizeof(MicPingPayload));
    MicStreamNegotiated = false;

    micSocket = INVALID_SOCKET;
    micPingThreadStarted = false;
    micSendLockCreated = false;
    micCryptoCtx = NULL;
    micNextSequence = 0;
    micLastTimestamp = 0;
    micLastSendMs = 0;
    micSequenceExhausted = false;
    atomic_store(&micStreamRunning, false);
    atomic_store(&micSentData, false);
}

int startMicStream(void) {
    int err;

    if (!MicStreamNegotiated) {
        return 0;
    }

    LC_ASSERT(MicPortNumber != 0);
    LC_ASSERT(!atomic_load(&micStreamRunning));

    memcpy(&micTargetAddr, &RemoteAddr, sizeof(micTargetAddr));
    SET_PORT(&micTargetAddr, MicPortNumber);

    micSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen, 0, SOCK_QOS_TYPE_AUDIO);
    if (micSocket == INVALID_SOCKET) {
        err = LastSocketFail();
        goto Fail;
    }

    micCryptoCtx = PltCreateCryptoContext(0);
    if (micCryptoCtx == NULL) {
        err = -1;
        goto Fail;
    }

    err = PltCreateMutex(&micSendLock);
    if (err != 0) {
        goto Fail;
    }
    micSendLockCreated = true;

    err = PltCreateThread("MicPing", sdsMicPingThreadProc, NULL, &micPingThread);
    if (err != 0) {
        goto Fail;
    }
    micPingThreadStarted = true;

    atomic_store(&micStreamRunning, true);
    Limelog("Microphone stream started (port %u)\n", MicPortNumber);
    return 0;

Fail:
    Limelog("Microphone stream start failed: %d\n", err);
    stopMicStream();
    return err;
}

void stopMicStream(void) {
    atomic_store(&micStreamRunning, false);
    while (atomic_load(&micSendersInFlight) != 0) {
        PltSleepMs(1);
    }

    if (micPingThreadStarted) {
        PltInterruptThread(&micPingThread);
        PltJoinThread(&micPingThread);
        micPingThreadStarted = false;
    }

    if (micSocket != INVALID_SOCKET) {
        closeSocket(micSocket);
        micSocket = INVALID_SOCKET;
    }

    if (micSendLockCreated) {
        PltDeleteMutex(&micSendLock);
        micSendLockCreated = false;
    }

    if (micCryptoCtx != NULL) {
        PltDestroyCryptoContext(micCryptoCtx);
        micCryptoCtx = NULL;
    }

    // Never keep negotiated state (ping payload, port) beyond the connection
    MicStreamNegotiated = false;
    MicPortNumber = 0;
    memset(&MicPingPayload, 0, sizeof(MicPingPayload));
}

bool LiIsMicrophoneStreamActive(void) {
    return atomic_load(&micStreamRunning);
}

int LiSendMicrophoneOpusData(const unsigned char* opusData, int opusLength) {
    unsigned char datagram[SDS_MIC_MAX_DATAGRAM];
    int ret;

    if (opusData == NULL || opusLength <= 0 || opusLength > SDS_MIC_MAX_OPUS_LENGTH) {
        return -1;
    }

    atomic_fetch_add(&micSendersInFlight, 1);
    if (!atomic_load(&micStreamRunning)) {
        atomic_fetch_sub(&micSendersInFlight, 1);
        return LI_ERR_UNSUPPORTED;
    }

    PltLockMutex(&micSendLock);

    if (micSequenceExhausted) {
        // DESIGN 7.2: the sequence never wraps; the mic stops at 2^32-1 packets (~2.7 years)
        ret = -1;
    }
    else {
        uint64_t now = PltGetMillis();
        bool firstFrame = micNextSequence == 0;
        uint32_t timestamp = sdsMicNextTimestamp(micLastTimestamp, firstFrame, now - micLastSendMs);

        ret = sdsMicEncryptPacket(micCryptoCtx, (const unsigned char*)StreamConfig.remoteInputAesKey,
                                  micNextSequence, timestamp, opusData, opusLength,
                                  datagram, sizeof(datagram));
        if (ret > 0) {
            if (micNextSequence == UINT32_MAX) {
                micSequenceExhausted = true;
            }
            else {
                micNextSequence++;
            }
            micLastTimestamp = timestamp;
            micLastSendMs = now;

            if (sendto(micSocket, (char*)datagram, ret, 0, (struct sockaddr*)&micTargetAddr, AddrLen) < 0) {
                // UDP is lossy anyway; the packet counts as sent so the sequence stays monotonic
                ret = LastSocketError();
                ret = ret != 0 ? -ret : -1;
            }
            else {
                ret = 0;
                atomic_store(&micSentData, true);
            }
        }
        else {
            ret = -1;
        }
    }

    PltUnlockMutex(&micSendLock);
    atomic_fetch_sub(&micSendersInFlight, 1);
    return ret;
}
