#!/bin/sh

#
# This is the nightly build script.
# It does almost nothing since the process itself is kept in CVS.
#
# This causes some bootstrap problems, but we deal with that by understanding
# that this first stage bootstrap can not updated automatically. This script
# should be copied somewhere that is not in the release tree (i.e. ~/bin)
# and invoked periodically.
#

if [ -f $HOME/openswan-2-regress-env.sh ]
then
    . $HOME/openswan-2-regress-env.sh
fi

# /btmp is a place with a bunch of space.
BTMP=${BTMP:-/btmp} export BTMP

GITPUBLIC=${GITPUBLIC-http://git.openswan.org/public/scm/openswan.git}

# BRANCH can also be set to test branches.
BRANCH=${BRANCH:-HEAD} export BRANCH

# rest of not to be touched.
YEAR=`date +%Y` export YEAR
MONTH=`date +%m` export MONTH
DAY=`date +%d` export DAY
TODAY=`date +%Y_%m_%d` export TODAY
TODAYSPLIT=`date +%Y/%m/%d` export TODAYSPLIT

BUILDSPOOL=$BTMP/$USER/$BRANCH/$TODAY export BUILDSPOOL

# go to subshell so that exit can abort that shell

(
mkdir -p $BUILDSPOOL || exit 3

cd $BUILDSPOOL || (echo "Can not make spool directory"; exit 4)

exec >$BUILDSPOOL/stdout.txt
exec 2>&1

# invoke file space cleanup first.
regress-cleanup.pl || (echo "Disk space cleanup failed"; exit 5)

# Now we clone git from the public repo
if [ -d openswan-2 ]
then
	echo "openswan-2 already exists - doing git pull"
	cd openswan-2
	git pull
	cd ..
else
	echo git clone $GITPUBLIC openswan-2
	git clone $GITPUBLIC openswan-2
	if [ $? != 0 ]
	then
        	echo "Failed to checkout source code. "
        	exit 10
	fi
fi

ln -s -f $BUILDSPOOL/openswan-2 $BTMP/$USER/$BRANCH/today


# invoke stage 2 now.
chmod +x $BUILDSPOOL/$TOPMODULE/testing/utils/regress-stage2.sh
$BUILDSPOOL/$TOPMODULE/testing/utils/regress-stage2.sh  || exit 6

# warn about changes in myself.
cmp $BUILDSPOOL/$TOPMODULE/testing/utils/regress-nightly.sh $0

if [ $? != 0 ]
then
    echo WARNING $BUILDSPOOL/$TOPMODULE/testing/utils/regress-nightly.sh differs from $0.
fi

)

# $Id: regress-nightly.sh,v 1.10 2003/11/21 23:07:03 mcr Exp $
#
# $Log: regress-nightly.sh,v $
# Revision 1.10  2003/11/21 23:07:03  mcr
# 	updates for hulk builds of openswan.
#
# Revision 1.9  2003/02/01 20:45:58  mcr
# 	moved regress results directory to be per year/month
#
# Revision 1.8  2003/01/24 16:21:41  build
#	moved capture of stdout/stderr to after disk space cleanup,
#	so that we can get better logging
#
# Revision 1.7  2002/05/24 03:24:04  mcr
# 	put all of build process into subshell so that regress-nightly.sh
# 	can be sourced, but the script can still exit nicely.
#
# Revision 1.4  2002/02/11 22:05:28  mcr
# 	initial scripts to export REGRESSRESULTS to support
# 	saving of testing results to a static area.
#
# Revision 1.3  2002/01/12 03:34:33  mcr
# 	an errant BUILDTOP remained. -> BUILDSPOOL.
#
# Revision 1.2  2002/01/11 22:14:31  mcr
# 	change BUILDTOP -> BUILDSPOOL.
# 	chmod +x all the scripts, just in case.
#
# Revision 1.1  2002/01/11 04:26:48  mcr
# 	revision 1 of nightly regress scripts.
#
#

