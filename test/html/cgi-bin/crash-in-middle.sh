#!/bin/sh

echo "Content-Type: text/plain"
echo

echo will crash 1 seconds later
sleep 1
exit 1
