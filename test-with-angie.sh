#!/bin/sh

set -eu

THIS_DIR="$(readlink -f "$(dirname "$0")")"
NGINX_REPO="https://github.com/webserver-llc/angie"
NGINX_DIR="$THIS_DIR/../angie"
NGINX_BIN="angie"
CFG_SCRIPT="./configure"

. "$THIS_DIR/test-with-nginx.sh"
