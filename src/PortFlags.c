#include "Limelight-internal.h"

// Port flag helpers formerly in ConnectionTester.c. The Internet connection tester
// (LiTestClientConnectivity) and the STUN client (LiFindExternalAddressIP4) were removed
// from this fork so that the library never contacts servers outside the LAN.

#define PORT_FLAGS_MAX_COUNT 32

unsigned int LiGetPortFlagsFromStage(int stage)
{
    switch (stage)
    {
        case STAGE_RTSP_HANDSHAKE:
            // GFE 3.22 requires a successful ping on 48000 to complete RTSP handshake
            return ML_PORT_FLAG_TCP_48010 | ML_PORT_FLAG_UDP_48010 | ML_PORT_FLAG_UDP_48000;

        case STAGE_CONTROL_STREAM_START:
            return ML_PORT_FLAG_UDP_47999;

        default:
            return 0;
    }
}

unsigned int LiGetPortFlagsFromTerminationErrorCode(int errorCode)
{
    switch (errorCode)
    {
        case ML_ERROR_NO_VIDEO_TRAFFIC:
            // Video is UDP 47998, but we'll also test UDP 48000 because
            // we don't have an equivalent audio traffic error.
            return ML_PORT_FLAG_UDP_47998 | ML_PORT_FLAG_UDP_48000;

        default:
            return 0;
    }
}

int LiGetProtocolFromPortFlagIndex(int portFlagIndex)
{
    // The lower byte is reserved for TCP
    return (portFlagIndex >= 8) ? IPPROTO_UDP : IPPROTO_TCP;
}

unsigned short LiGetPortFromPortFlagIndex(int portFlagIndex)
{
    switch (portFlagIndex)
    {
        // TCP ports
        case ML_PORT_INDEX_TCP_47984:
            return 47984;
        case ML_PORT_INDEX_TCP_47989:
            return 47989;
        case ML_PORT_INDEX_TCP_48010:
            return 48010;

        // UDP ports
        case ML_PORT_INDEX_UDP_47998:
            return 47998;
        case ML_PORT_INDEX_UDP_47999:
            return 47999;
        case ML_PORT_INDEX_UDP_48000:
            return 48000;
        case ML_PORT_INDEX_UDP_48010:
            return 48010;

        default:
            LC_ASSERT(false);
            return 0;
    }
}

void LiStringifyPortFlags(unsigned int portFlags, const char* separator, char* outputBuffer, int outputBufferLength)
{
    // Initialize the output buffer to an empty string
    outputBuffer[0] = 0;

    // If there is no separator specified, use an empty string
    if (separator == NULL) {
        separator = "";
    }

    int offset = 0;
    for (int i = 0; i < PORT_FLAGS_MAX_COUNT; i++) {
        if (portFlags & (1U << i)) {
            const char* protoStr = LiGetProtocolFromPortFlagIndex(i) == IPPROTO_UDP ? "UDP" : "TCP";
            offset += snprintf(&outputBuffer[offset], outputBufferLength - offset, "%s%s %u",
                               offset != 0 ? separator : "",
                               protoStr,
                               LiGetPortFromPortFlagIndex(i));
            if (outputBufferLength - offset <= 0) {
                // snprintf() will return the desired length if the buffer is too small,
                // so it is possible for this calculation to be negative.
                break;
            }
        }
    }
}
