#!/bin/bash

if [[ -z $2 ]]; then 
    echo "Usage: $0 <path> <string>"
    exit 1;
fi

files=`find $1`

for file in $files; do 
    if [[ -f $file ]]; then 
        grep "$2" $file 
    fi
done


