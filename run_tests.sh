#!/bin/bash

set -e

THIS_DIR=$(dirname "$(readlink -f "$0")")
cd "$THIS_DIR"

export PERL5LIB="$THIS_DIR/test/lib:$PERL5LIB"
export TEST_ROOT_DIR="$THIS_DIR/test/www"
prove -r test/tests
