#!/bin/sh

echo "Content-Type: text/plain"
echo

read n
n=$(echo "$n" | tr -d '\r')
echo "n = $n"
exec <&-

for i in $(seq "$n"); do
  sleep 1
  echo $i
done
