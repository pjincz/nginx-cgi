#!/bin/bash

echo "Content-Type: text/plain"
echo

export | sed 's/declare -x //'
