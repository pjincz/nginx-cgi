#!/bin/sh

set -eu

THIS_DIR="$(readlink -f "$(dirname "$0")")"
NGINX_REPO=https://github.com/nginx/nginx
NGINX_DIR="$THIS_DIR/../nginx"

JOBS=$(nproc 2>/dev/null \
      || sysctl -n hw.ncpu 2>/dev/null \
      || getconf _NPROCESSORS_ONLN 2>/dev/null \
      || echo 4)

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
    (cd "$NGINX_DIR" && ./auto/configure --add-dynamic-module=$THIS_DIR --with-debug)
fi

(cd "$NGINX_DIR" && make -j "$JOBS")

TEST_NGINX_BINARY="$NGINX_DIR/objs/nginx" ./run_tests.sh
