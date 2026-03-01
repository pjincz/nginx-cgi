#!/bin/sh

echo "Content-Type: text/plain"
echo

echo "a_magic_string" >&2

# remove following line, when issue 21 fixed
# https://github.com/pjincz/nginx-cgi/issues/21
sleep 1

echo okay
