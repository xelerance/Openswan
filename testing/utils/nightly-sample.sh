#!/bin/sh

. /etc/profile

USER=${USER-build} export USER
LANG=C export LANG

. ~build/bin/regress_branch.sh


# make sure that $HOME/bin/touch is before /bin/touch.
PATH=$HOME/bin:~build/bin:$PATH export PATH

if [ ! -f $HOME/WANTSNAP/doingtest ]
then
        echo $$ >~build/WANTSNAP/doingtest
fi

# source it so that we get the settings for $TODAY
source $HOME/openswan-2-regress-env.sh

BRANCH=HEAD export BRANCH

( regress_branch )

#BRANCH=PRE2_3 export BRANCH

#( regress_branch )

#BRANCH=PRE2_2dr2 export BRANCH

#( regress_branch )

rm -f $HOME/WANTSNAP/doingtest

