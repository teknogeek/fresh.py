#!/bin/bash

if [[ "$#" -eq 0 ]]; then
    echo "Usage: clean.sh <input_file> [regex_pattern_file]"
    exit 1
fi

REGEX_FILE="${2:-$(dirname ${BASH_SOURCE[0]})/clean_regex.txt}"
if [ -f "$1" ]; then
    egrep -vf $REGEX_FILE $1
else
    echo "File '$1' does not exist!"
fi
