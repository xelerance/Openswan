#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-bigicmp-01
TESTHOST=west
EXITONEMPTY=--exitonempty
ARPREPLY=--arpreply 

PUBINPUT=../inputs/espfrags1.pcap
REFPRIVOUTPUT=spi1-cleartext.txt
REFCONSOLEOUTPUT=spi1-console.txt
REFCONSOLEFIXUPS="kern-list-fixups.sed nocr.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS klips-spi-sanitize.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS klips-debug-sanitize.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS ipsec-look-sanitize.sed"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758 -v"
SCRIPT=spi1-in.sh

#NETJIGDEBUG=true


