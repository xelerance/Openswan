#!/bin/sh

set -e && make programs

for f in $(make testlist)
do
    (cd $f; figlet -t $f; rm -f core;
     while ! make check && ! [ -f core ];
     do
         make update && git add -p .
     done
    )
done

