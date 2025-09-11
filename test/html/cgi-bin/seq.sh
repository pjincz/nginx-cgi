#!/bin/sh

echo "Content-Type: text/plain"
echo

n=$(echo "$QUERY_STRING" | sed 's/&/\n/' | sed -n "s/^n=//p")

seq "${n:-100}"
