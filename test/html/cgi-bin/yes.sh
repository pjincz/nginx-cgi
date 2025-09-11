#!/bin/sh

echo "Content-Type: text/plain"
echo

w=$(echo "$QUERY_STRING" | tr '&' '\n' | sed -n "s/^w=//p")
n=$(echo "$QUERY_STRING" | tr '&' '\n' | sed -n "s/^n=//p")

yes "${w:-yes}" | head -n "${n:-1000}"
