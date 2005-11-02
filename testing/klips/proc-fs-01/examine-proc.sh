#!/bin/sh
TZ=GMT export TZ

ls -l /proc/net/ipsec_*
find /proc/net/ipsec -ls

