// secure-desktop-stream: microphone passthrough (client -> host).
//
// Wire format and negotiation are specified in docs/DESIGN.md section 7 of the
// secure-desktop-stream repository. Summary:
//
//   datagram = header[12] || tag[16] || AES-128-GCM(rikey, iv, aad = header, opus)
//   header   = version(1) flags(0) reserved16(0) sequence32be timestamp32be
//   iv[12]   = sequence32le || 00 00 00 00 00 00 || 'C' || 'M'
//
// The host binds the UDP source endpoint of the first valid SS_PING (20 bytes)
// carrying the X-SS-Ping-Payload from the RTSP SETUP streamid=mic response.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "Limelight-internal.h"

#define SDS_MIC_VERSION          1
#define SDS_MIC_HEADER_SIZE      12
#define SDS_MIC_TAG_SIZE         16
#define SDS_MIC_IV_SIZE          12
#define SDS_MIC_KEY_SIZE         16
#define SDS_MIC_MAX_DATAGRAM     1400
#define SDS_MIC_MAX_OPUS_LENGTH  (SDS_MIC_MAX_DATAGRAM - SDS_MIC_HEADER_SIZE - SDS_MIC_TAG_SIZE)

// 48 kHz sample clock, 20 ms frames
#define SDS_MIC_SAMPLE_RATE      48000
#define SDS_MIC_FRAME_SAMPLES    960

// Ping cadence: every 500 ms until the first mic packet was sent, then every 5 s
#define SDS_MIC_PING_FAST_MS     500
#define SDS_MIC_PING_SLOW_MS     5000

// After this many milliseconds without a sent frame, the timestamp jumps by the
// elapsed wall-clock time so the host can tell a pause (mute) from packet loss.
#define SDS_MIC_PAUSE_THRESHOLD_MS 100

// Pure framing helpers (no globals, no sockets). Exposed for unit tests.
void sdsMicBuildIv(uint32_t sequence, unsigned char iv[SDS_MIC_IV_SIZE]);
void sdsMicBuildHeader(uint32_t sequence, uint32_t timestamp, unsigned char header[SDS_MIC_HEADER_SIZE]);

// Encrypts one Opus frame into a complete datagram.
// Returns the datagram length, or -1 on invalid arguments or crypto failure.
// outCapacity must be at least SDS_MIC_HEADER_SIZE + SDS_MIC_TAG_SIZE + opusLength.
int sdsMicEncryptPacket(PPLT_CRYPTO_CONTEXT ctx, const unsigned char key[SDS_MIC_KEY_SIZE],
                        uint32_t sequence, uint32_t timestamp,
                        const unsigned char* opusData, int opusLength,
                        unsigned char* out, int outCapacity);

// Advances the 48 kHz timestamp for the next frame. elapsedMs is the wall-clock time
// since the previous frame was sent (ignored for the first frame).
uint32_t sdsMicNextTimestamp(uint32_t previousTimestamp, bool firstFrame, uint64_t elapsedMs);

// Connection lifecycle (called from Connection.c / RtspConnection.c)
extern uint16_t MicPortNumber;
extern SS_PING MicPingPayload;
extern bool MicStreamNegotiated;

void initializeMicStream(void);
int startMicStream(void);
void stopMicStream(void);
