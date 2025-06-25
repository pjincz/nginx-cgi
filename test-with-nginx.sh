#!/bin/sh

set -eu

THIS_DIR="$(readlink -f "$(dirname "$0")")"
NGINX_REPO="${NGINX_REPO:-https://github.com/nginx/nginx}"
NGINX_DIR="${NGINX_DIR:-$THIS_DIR/../nginx}"
NGINX_BIN="${NGINX_BIN:-nginx}"
CFG_SCRIPT="${CFG_SCRIPT:-./auto/configure}"

JOBS=$(nproc 2>/dev/null \
      || sysctl -n hw.ncpu 2>/dev/null \
      || getconf _NPROCESSORS_ONLN 2>/dev/null \
      || echo 4)

CC=
if which cc; then
    CC=cc
elif which clang; then
    CC=clang
elif which gcc; then
    CC=gcc
else
    echo "no compiler found" >&2
    exit 1
fi

OS="$(uname -s)"

SYSTEM_SUPPORT_ASAN=0
if [ "$OS" = "Linux" ]; then
    SYSTEM_SUPPORT_ASAN=1
elif [ "$OS" = "FreeBSD" ]; then
    SYSTEM_SUPPORT_ASAN=1
fi

WITH_ASAN="${WITH_ASAN:-$SYSTEM_SUPPORT_ASAN}"

if [ "$WITH_ASAN" = "1" ]; then
    CC_OPT="-O0 -DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC -fsanitize=address"
    LD_OPT="-fsanitize=address"

    if cc -v 2>&1 | grep -q gcc; then
        # On gcc 9.4, asan reports false stack-overflow error
        # disable it with `--param asan-stack=0`
        CC_OPT="$CC_OPT  --param asan-stack=0"
    fi

    # nginx has odr violation problem, just ignore it
    # nginx has memory leaking problem, ignore it for now
    export ASAN_OPTIONS=detect_odr_violation=0,detect_leaks=0
else
    CC_OPT="-O0 -DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC"
    LD_OPT=""
fi

if [ ! -d "$NGINX_DIR" ]; then
    git clone --depth=1 "$NGINX_REPO" "$NGINX_DIR"
fi

# automatically remove bad Makefile
if [ -f "$NGINX_DIR/Makefile" ]; then
    if ! grep -q "build:" "$NGINX_DIR/Makefile"; then
        rm "$NGINX_DIR/Makefile"
    fi
fi

if [ ! -f "$NGINX_DIR/Makefile" ]; then
    (cd "$NGINX_DIR" && \
     "$CFG_SCRIPT" --add-dynamic-module="$THIS_DIR" \
                   --with-cc="$CC" --with-cc-opt="$CC_OPT" \
                   --with-ld-opt="$LD_OPT" --with-debug)
fi

(cd "$NGINX_DIR" && make -j "$JOBS")

TEST_NGINX_BINARY="$NGINX_DIR/objs/$NGINX_BIN" ./run_tests.sh
