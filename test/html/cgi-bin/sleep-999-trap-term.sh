#!/bin/sh

set -e

echo "Content-Type: text/plain"
echo

trap '' TERM

echo before sleep

i=0
while [ "$i" -lt 999 ]; do
    sleep 1
    i=$((i+1))
done

echo sleep done
