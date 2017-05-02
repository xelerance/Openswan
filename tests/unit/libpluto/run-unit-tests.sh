#!/bin/sh

for f in $(make testlist)
do
    (cd $f; echo; echo $f $f $f $f;
     echo; echo;
     while ! make check;
     do
         make update && git add -p .
     done
    )
done

