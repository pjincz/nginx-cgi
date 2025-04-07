#!/bin/sh

set -eu

THIS_DIR="$(readlink -f "$(dirname "$0")")"
ANGIE_REPO=https://github.com/webserver-llc/angie
ANGIE_DIR="$THIS_DIR/../angie"

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

if [ ! -d "$ANGIE_DIR" ]; then
    git clone --depth=1 "$ANGIE_REPO" "$ANGIE_DIR"
fi

# automatically remove bad Makefile
if [ -f "$ANGIE_DIR/Makefile" ]; then
    if ! grep -q "build:" "$ANGIE_DIR/Makefile"; then
        rm "$ANGIE_DIR/Makefile"
    fi
fi

if [ ! -f "$ANGIE_DIR/Makefile" ]; then
    (cd "$ANGIE_DIR" && ./configure --add-dynamic-module="$THIS_DIR" --with-cc="$CC" --with-debug)
fi

(cd "$ANGIE_DIR" && make -j "$JOBS")

TEST_NGINX_BINARY="$ANGIE_DIR/objs/angie" ./run_tests.sh
