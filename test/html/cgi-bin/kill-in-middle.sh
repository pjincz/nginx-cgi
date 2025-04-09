#!/bin/sh

echo "Content-Type: text/plain"
echo

echo will be killed 1 seconds later
sleep 1
kill $$
