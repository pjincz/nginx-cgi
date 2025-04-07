#!/bin/sh

set -eu

THIS_DIR="$(readlink -f "$(dirname "$0")")"
ANGIE_REPO=https://github.com/webserver-llc/angie
ANGIE_DIR="$THIS_DIR/../angie"

JOBS=$(nproc 2>/dev/null \
      || sysctl -n hw.ncpu 2>/dev/null \
      || getconf _NPROCESSORS_ONLN 2>/dev/null \
      || echo 4)

if [ ! -d "$ANGIE_DIR" ]; then
    git clone "$ANGIE_REPO" "$ANGIE_DIR"
fi

if [ ! -f "$ANGIE_DIR/Makefile" ]; then
    (cd "$ANGIE_DIR" && ./configure --add-dynamic-module=$THIS_DIR --with-debug)
fi

(cd "$ANGIE_DIR" && make -j "$JOBS")

TEST_NGINX_BINARY="$ANGIE_DIR/objs/angie" ./run_tests.sh
