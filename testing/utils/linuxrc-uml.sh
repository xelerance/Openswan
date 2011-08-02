#!/bin/bash

PATH="/sbin:/bin"


# defaults
tmpfs_size="10M"
udev_root="/root/dev"

. funcs.sh

##############################################################################

mount -n -t proc none /proc
if grep SHELL /proc/cmdline; then echo STARTING SHELL - exit to continue; /bin/bash; fi

for v in $(cat /proc/cmdline)
do
	case $v in
	umlroot=*) hostfsroot=${v#umlroot=};;
	esac
done

echo MOUNTING $hostfsroot for UML testing root.
mount -n -o $hostfsroot -t hostfs none /root

echo 256 >/proc/sys/kernel/real-root-dev

if ! grep -q '[[:space:]]tmpfs$' /proc/filesystems; then
  echo "udev requires tmpfs support, not started."
  exit 0
fi

##############################################################################

udev_root=${udev_root%/}

mount_tmpfs
echo -n "Creating initial device nodes..."
make_extra_nodes
echo "done."

echo Invoked with Arguments: $*

cd /root
mount -n -t proc none /proc 
mount -n --move . /
if grep LATE /proc/cmdline; then echo STARTING SHELL2 - exit to continue; /bin/bash; fi
exec </dev/console >/dev/console 2>&1
exec /usr/sbin/chroot . /sbin/init $*

