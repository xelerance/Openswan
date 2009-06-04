# mount a tmpfs over /dev, if somebody did not already do it
mount_tmpfs() {
  if grep -E -q "^[^[:space:]]+ /dev tmpfs" /proc/mounts; then
    return 0
  fi

  # /dev/.static/dev/ is used by MAKEDEV to access the real /dev/ directory.
  # /etc/udev/ is recycled as a temporary mount point because it's the only
  # directory which is guaranteed to be available.

  echo -n "Mounting a tmpfs over /dev..."
  if ! mount -n -o size=$tmpfs_size,mode=0755 -t tmpfs tmpfs /root/dev; then
    echo " FAILED!"
    echo "FATAL: udev requires tmpfs support, not started."
    umount /etc/udev
    exit 1
  fi

  # using ln to test if /dev works, because touch is in /usr/bin/
  if ln -s test /root/dev/test-file; then
    rm /root/dev/test-file
    echo "done."
  else
    echo " FAILED!"
    echo "FATAL: udev requires tmpfs support, not started."
    umount /dev
    exit 1
  fi
}

# I hate this hack.  -- Md
make_extra_nodes() {
  [ -e /root/etc/udev/links.conf ] || return 0
  grep '^[^#]' /root/etc/udev/links.conf | \
  while read type name arg1; do
    [ "$type" -a "$name" -a ! -e "/root/dev/$name" -a ! -L "/root/dev/$name" ] || continue
    case "$type" in
      L) ln -s $arg1 /root/dev/$name ;;
      D) mkdir -p /root/dev/$name ;;
      M) mknod --mode=600 /root/dev/$name $arg1 ;;
      *) echo "links.conf: unparseable line ($type $name $arg1)" ;;
    esac
  done
  [ -c /root/dev/console ] || mknod /root/dev/console c 5 1
  [ -c /root/dev/null ] || mknod /root/dev/null c 1 3
}
