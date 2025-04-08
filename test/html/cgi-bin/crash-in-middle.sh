#!/bin/sh

echo "Content-Type: text/plain"
echo

echo will crash 3 seconds later
sleep 3
exit 1
