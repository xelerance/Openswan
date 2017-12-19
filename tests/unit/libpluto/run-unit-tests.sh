#!/bin/sh

# set some funky toilet options
toilet_options=
[ -t 0 ] && toilet_options="--metal --width $(tput cols) --font future"

header() {
    # use tilet if possible
    toilet $toilet_options $@ \
    || figlet -t $@
}

for f in $(make testlist)
do
    (cd $f ; header $f
     while ! make check;
     do
         make update && git add -p .
     done
    )
done

