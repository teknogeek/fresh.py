#!/bin/bash

REGEX_FILE="$PWD/clean_regex.txt"
if [ -f "$1" ]; then
    egrep -vf $REGEX_FILE $1
else
    echo "File '$1' does not exist!"
fi
