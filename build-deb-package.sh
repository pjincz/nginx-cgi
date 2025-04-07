#!/bin/sh

set -eu

die() {
    echo "$*" >&2
    exit 1
}

if ! which debuild 2>/dev/null; then
    if ! which apt 2>/dev/null; then
        die "$0 can only work with deb system"
    fi
    echo "$0 needs to install build toolchain, type password to continue, or ^C to quit."
    sudo apt install build-essential devscripts dpkg-dev fakeroot -y
    sudo apt build-dep . -y
fi

debuild -us -uc
