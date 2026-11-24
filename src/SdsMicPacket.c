// secure-desktop-stream: microphone packet framing (see SdsMic.h)
#include "SdsMic.h"

void sdsMicBuildIv(uint32_t sequence, unsigned char iv[SDS_MIC_IV_SIZE]) {
    // NIST SP 800-38D 8.2.1 deterministic construction: the sequence number is the
    // invocation field and 'CM' (client-originated, microphone) is the fixed field.
    // Control uses 'C'/'H' + 'C', RTSP '?' + 'R' and video '?' + 'V' in byte 11, so
    // IVs never collide across streams that share the rikey.
    memset(iv, 0, SDS_MIC_IV_SIZE);
    iv[0] = (unsigned char)(sequence >> 0);
    iv[1] = (unsigned char)(sequence >> 8);
    iv[2] = (unsigned char)(sequence >> 16);
    iv[3] = (unsigned char)(sequence >> 24);
    iv[10] = (unsigned char)'C';
    iv[11] = (unsigned char)'M';
}

void sdsMicBuildHeader(uint32_t sequence, uint32_t timestamp, unsigned char header[SDS_MIC_HEADER_SIZE]) {
    header[0] = SDS_MIC_VERSION;
    header[1] = 0; // flags (reserved, must be 0)
    header[2] = 0; // reserved
    header[3] = 0;
    header[4] = (unsigned char)(sequence >> 24);
    header[5] = (unsigned char)(sequence >> 16);
    header[6] = (unsigned char)(sequence >> 8);
    header[7] = (unsigned char)(sequence >> 0);
    header[8] = (unsigned char)(timestamp >> 24);
    header[9] = (unsigned char)(timestamp >> 16);
    header[10] = (unsigned char)(timestamp >> 8);
    header[11] = (unsigned char)(timestamp >> 0);
}

int sdsMicEncryptPacket(PPLT_CRYPTO_CONTEXT ctx, const unsigned char key[SDS_MIC_KEY_SIZE],
                        uint32_t sequence, uint32_t timestamp,
                        const unsigned char* opusData, int opusLength,
                        unsigned char* out, int outCapacity) {
    unsigned char iv[SDS_MIC_IV_SIZE];
    int cipherLength = 0;

    if (ctx == NULL || key == NULL || opusData == NULL || out == NULL ||
            opusLength <= 0 || opusLength > SDS_MIC_MAX_OPUS_LENGTH ||
            outCapacity < SDS_MIC_HEADER_SIZE + SDS_MIC_TAG_SIZE + opusLength) {
        return -1;
    }

    sdsMicBuildHeader(sequence, timestamp, out);
    sdsMicBuildIv(sequence, iv);

    if (!PltEncryptMessageAead(ctx, (unsigned char*)key, SDS_MIC_KEY_SIZE,
                               iv, sizeof(iv),
                               out, SDS_MIC_HEADER_SIZE,
                               &out[SDS_MIC_HEADER_SIZE], SDS_MIC_TAG_SIZE,
                               opusData, opusLength,
                               &out[SDS_MIC_HEADER_SIZE + SDS_MIC_TAG_SIZE], &cipherLength)) {
        return -1;
    }

    if (cipherLength != opusLength) {
        return -1;
    }

    return SDS_MIC_HEADER_SIZE + SDS_MIC_TAG_SIZE + cipherLength;
}

uint32_t sdsMicNextTimestamp(uint32_t previousTimestamp, bool firstFrame, uint64_t elapsedMs) {
    uint64_t advance;

    if (firstFrame) {
        return 0;
    }

    if (elapsedMs <= SDS_MIC_PAUSE_THRESHOLD_MS) {
        return previousTimestamp + SDS_MIC_FRAME_SAMPLES;
    }

    // Resuming after a pause (mute or capture stall): advance by the elapsed time in
    // whole frames so the host sees a discontinuity rather than a run of lost packets.
    advance = (elapsedMs * (SDS_MIC_SAMPLE_RATE / 1000)) / SDS_MIC_FRAME_SAMPLES * SDS_MIC_FRAME_SAMPLES;
    if (advance < SDS_MIC_FRAME_SAMPLES) {
        advance = SDS_MIC_FRAME_SAMPLES;
    }

    return previousTimestamp + (uint32_t)advance;
}
