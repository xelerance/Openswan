#!/bin/sh

#
# This script is used to generate secondary lines for putting into the
# nic machine's named.conf. It uses the file "zones.txt" as input.
#
# This zone should contain lines like:
#   zonename.foo.bar.             {beet,carrot}
#
#

echo "// These lines generated with the gen-primaries.sh script"

cat zones.txt | sed -e '/^#/d' -e '/^$/d' | while read zone master rest
do
    echo 'zone "'$zone'" { type master;  file "/etc/bind/db.'$zone'.signed"; };'
done

































#
# $Log: gen-primaries.sh,v $
# Revision 1.2  2002/11/28 04:59:57  mcr
# 	generate list of zones for "nic" machine.
#
# Revision 1.1  2002/11/27 19:43:09  mcr
# 	added . to list of zones.
# 	changed named.conf to be primary on "nic"
#
# Revision 1.1  2002/10/24 05:35:46  mcr
# 	file/script to generate secondary list.
#
#
