KERNPOOL=/distros/kernel/linux-2.4.17
UMLPATCH=/abigail/user-mode-linux/uml-patch-2.4.17-10.bz2
BASICROOT=/abigail/user-mode-linux/root-6.0
SHAREDIR=${BASICROOT}/usr/share

REGRESSTREE=/freeswan/mgmt/regress
TCPDUMP=tcpdump-3.7.1 export TCPDUMP

KERNEL_LINUS2_0_SRC=
KERNEL_LINUS2_2_SRC=
KERNEL_LINUX2_4_SRC=
KERNEL_RH7_2_SRC=/a3/kernel_sources/rh/linux-2.4.9-13/
KERNEL_RH7_3_SRC=/a3/kernel_sources/rh/linux-2.4.18-17.7.x

#NIGHTLY_WATCHERS="mcr@freeswan.org"
NIGHTLY_WATCHERS="mcr@freeswan.org,hugh@freeswan.org,rgb@freeswan.org,dhr@freeswan.org,gnu@freeswan.org"

FAILLINES=128

PATH=$PATH:/sandel/bin export PATH
CVSROOT=:pserver:anoncvs@ip212.xs4net.freeswan.org:/freeswan/MASTER
CVSUMASK=002 
export CVSROOT CVSUMASK

SNAPSHOTSIGDIR=$HOME/snapshot-sig
LASTREL=1.97

DISTUSER=freeswan
DISTHOST=xs4.xs4all.nl
DISTDIR=FTP

# XS4ALL only support SSH1!
scp=/usr/bin/scp
ssh=/usr/bin/ssh


