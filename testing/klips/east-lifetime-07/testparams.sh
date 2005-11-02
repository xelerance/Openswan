#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=east-lifetime-07
TESTHOST=east
EXITONEMPTY=--exitonempty
ARPREPLY=--arpreply
REFPUBOUTPUT=../east-icmp-01/spi1-output.txt
PRIVINPUT=../inputs/01-sunrise-sunset-ping.pcap
REFCONSOLEOUTPUT=test-07-console.txt
REFCONSOLEFIXUPS="kern-list-fixups.sed nocr.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS klips-spi-sanitize.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS klips-debug-sanitize.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS ipsec-look-sanitize.sed"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758"
SCRIPT=test01.sh




