#!/bin/bash

echo "Content-Type: text/plain"
echo

declare -A qs
for kv in ${QUERY_STRING//&/ }; do
    key=${kv%%=*}
    val=${kv#*=}
    qs["$key"]=$val
done

yes "${qs[w]:-yes}" | head -n "${qs[n]:-1000}"
