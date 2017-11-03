#!/bin/sh

set -e && make programs

rm -f */core

for f in $(make testlist)
do
    (cd $f; figlet -t $f; rm -f core;
     while ! make check && ! [ -f core ];
     do
         make update && git add -p .
     done
    )
done

if [ -f */core ]; then
   exit 10
fi
