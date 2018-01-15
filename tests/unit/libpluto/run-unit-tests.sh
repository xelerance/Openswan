#!/bin/sh

# set some funky toilet options
toilet_options=
[ -t 0 ] && toilet_options="--metal --width $(tput cols) --font future"

header() {
    # use tilet if possible
    toilet $toilet_options $@ \
    || figlet -t $@
}

set -e && make programs

rm -f */core

for f in $(make testlist)
do
    (cd $f; header $f; rm -f core;
     while ! make check && ! [ -f core ];
     do
         make update && git add -p .
     done
    )
done

if [ -f */core ]; then
   exit 10
fi
