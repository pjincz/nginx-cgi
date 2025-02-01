#!/bin/sh

echo "Content-Type: text/plain"
echo

echo hello

# close stdin stdout
exec <&-
exec >&-

# output a delay error message
sleep 1
echo 'test error' >&2
