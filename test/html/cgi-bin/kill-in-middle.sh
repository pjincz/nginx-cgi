#!/bin/sh

echo "Content-Type: text/plain"
echo

echo will be killed 3 seconds later
sleep 3
kill $$
