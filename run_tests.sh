#!/bin/sh

set -e

THIS_DIR=$(dirname "$(readlink -f "$0")")
cd "$THIS_DIR"

export PERL5LIB="$THIS_DIR/test/lib:$PERL5LIB"
export TEST_ROOT_DIR="$THIS_DIR/test/html"

VERBOSE=
if [ -n "$TEST_NGINX_VERBOSE" ]; then
    VERBOSE=-v
fi

if [ "$#" -gt 0 ]; then
    prove "$@" $VERBOSE
else
    prove -r test/tests $VERBOSE
fi
