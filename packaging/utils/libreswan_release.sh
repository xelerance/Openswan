#!/bin/sh

OS_CVS=anoncvs@anoncvs.libreswan.org:/cvs/libreswan
OS_FTP=$USER@localhost:/tmp
GNUPGHOME=/mnt/build/libreswan-2
export GNUPGHOME OS_CVS OS_FTP


echo "Checking out CVS ..."
rm -rf libreswan-$1 > /dev/null
cvs -z9 -d $OS_CVS co libreswan-2

mv libreswan-2 libreswan-$1
cd libreswan-$1

echo "Fixing Makefile.inc..."
cat Makefile.inc | sed s/^USE_LWRES.*/USE_LWRES?=false/ > Makefile.inc2 && mv Makefile.inc2 Makefile.inc


echo "I am setting the Version info..."
cat Makefile.ver | sed s/2.CVSHEAD/$1/ > Makefile.ver2 && mv Makefile.ver2 Makefile.ver
cat packaging/redhat/libreswan.26spec | sed s/2.CVSHEAD/$1/ > n && mv n packaging/redhat/libreswan.26spec
cat packaging/redhat/libreswan.spec | sed s/2.CVSHEAD/$1/ > n && mv n packaging/redhat/libreswan.spec
cat packaging/suse/libreswan.26spec | sed s/2.CVSHEAD/$1/ > n && mv n packaging/suse/libreswan.26spec
echo "If there were any errors above, abort now... [2 second pause]"
sleep 2


# TAG CVS
echo "Tagging CVS..."
TAG=`echo $1 | sed s/\\\./_/g`
cvs tag v$TAG

echo "Removing CVS bits (CVS dirs, .cvsignore files, etc...)"
# Clean up CVS remnants
find ./ -name CVS | xargs rm -rf
find ./ -name .cvsignore | xargs rm -rf
cd  ..
echo "Creating & Signing Package..."
tar -czf libreswan-$1.tar.gz libreswan-$1
echo "Building patches..."
cd libreswan-$1
make kernelpatch2.4 > ../libreswan-$1.kernel-2.4-klips.patch
make kernelpatch2.6 > ../libreswan-$1.kernel-2.6-klips.patch
make nattpatch2.4 > ../libreswan-$1.kernel-2.4-natt.patch
make nattpatch2.6 > ../libreswan-$1.kernel-2.6-natt.patch
cd  ..
# Compress patches
gzip libreswan-$1.kernel-2.4-klips.patch
gzip libreswan-$1.kernel-2.4-natt.patch
gzip libreswan-$1.kernel-2.6-klips.patch
gzip libreswan-$1.kernel-2.6-natt.patch
# Sign binaries
gpg -sba libreswan-$1.tar.gz 
gpg -sba libreswan-$1.kernel-2.4-klips.patch.gz
gpg -sba libreswan-$1.kernel-2.4-natt.patch.gz
gpg -sba libreswan-$1.kernel-2.6-klips.patch.gz
gpg -sba libreswan-$1.kernel-2.6-natt.patch.gz
chmod 644 libreswan-$1*.asc

echo "Uploading to ftp/www sites..."
scp libreswan-$1.*.gz* $OS_FTP
scp libreswan-$1/CHANGES $OS_FTP

# Move to old/ since we're done.
mv libreswan-$1* old/ 
echo "Releasing Process Done"
