#!/bin/sh

klips_git=/mara1/git/klips
openswan_git=`pwd`
patchdir=$openswan_git/linux/patches

# generate set of patches against last time we did this, and apply
# the patches to the linux/ subtree.
cd $klips_git

mkdir -p $patchdir
git-format-patch -o $openswan_git/linux/patches --mbox openswan_klips

SIGNOFF="Michael Richardson <mcr@xelerance.com>"
mkdir .dotest

cd $openswan_git/linux
for p in patches/0*.txt
do
    rm -rf .dotest && mkdir -p .dotest
    num_msgs=$(git-mailsplit "$p" .dotest) || exit 1

    set -- x .dotest/0*
    shift
    while case "$#" in 0) break;; esac
    do
	i="$1"
	git-mailinfo -k .dotest/msg .dotest/patch <$i >.dotest/info
	git-stripspace <.dotest/msg >.dotest/msg-clean
	sed -e 's|^\+\+\+ b/net|+++ b/linux/net|' -e 's|^--- a/net|--- a/linux/net|' <.dotest/patch >.dotest/patch-osw
	cat .dotest/patch-osw
	(cd $openswan_git && git-applypatch linux/.dotest/msg-clean linux/.dotest/patch-osw linux/.dotest/info "$SIGNOFF" )
	shift
    done
done

cd $klips_git
cg-switch openswan_klips
git pull . klipsNG
cg-switch klipsNG


