#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=klipstest

TESTNAME=east-1des-01
TESTHOST=east
HOST_START=$POOLSPACE/$TESTHOST/startmodule.sh
EXITONEMPTY=--exitonempty
PRIV_INPUT=../inputs/01-sunrise-sunset-ping.pcap

#THREEEIGHT=true
REF_PUB_OUTPUT=spi1-output.txt
REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-n -E des-cbc-hmac96:0x4043434545464646"
INIT_SCRIPT=spi1.sh

PACKETRATE=100

