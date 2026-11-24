#!/usr/bin/env sh
# Build and run the secure-desktop-stream microphone tests with the system C compiler.
# Usage: tests/run-sds-mic-test.sh [output-dir]   (needs OpenSSL headers; uses pkg-config if present)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-${TMPDIR:-/tmp}}
CFLAGS_SSL=$(pkg-config --cflags libcrypto 2>/dev/null || true)
LIBS_SSL=$(pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)
COMMON_CFLAGS="-std=c11 -Wall -Wextra -Wno-unused-parameter -Werror -O1 -DHAS_SOCKLEN_T"

${CC:-cc} $COMMON_CFLAGS -I"$ROOT/src" -I"$ROOT/enet/include" $CFLAGS_SSL \
  "$ROOT/tests/sds_mic_test.c" "$ROOT/src/SdsMicPacket.c" "$ROOT/src/PlatformCrypto.c" \
  $LIBS_SSL -o "$OUT/sds_mic_test"
"$OUT/sds_mic_test"

${CC:-cc} $COMMON_CFLAGS ${SDS_TEST_SANITIZE:-} -I"$ROOT/src" -I"$ROOT/enet/include" $CFLAGS_SSL \
  "$ROOT/tests/sds_mic_stream_test.c" "$ROOT/src/SdsMicStream.c" \
  "$ROOT/src/SdsMicPacket.c" "$ROOT/src/PlatformCrypto.c" "$ROOT/src/Platform.c" "$ROOT/src/PlatformSockets.c" \
  $LIBS_SSL -lpthread -o "$OUT/sds_mic_stream_test"
"$OUT/sds_mic_stream_test"
