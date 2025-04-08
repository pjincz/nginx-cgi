#!/bin/sh

echo "Content-Type: text/plain"
echo

echo "$$ is running background"
exec </dev/null >/dev/null 2>&1

sleep 999

