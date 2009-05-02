#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=klipstest

TESTNAME=east-icmp-07
TESTHOST=east

EXITONEMPTY=--exitonempty
PRIV_INPUT=../inputs/01-sunrise-sunset-ping.pcap
#THREEEIGHT=true

REF_PUB_OUTPUT=spi1-output.txt

REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt

REF_CONSOLE_FIXUPS="script-only.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"

# openssl doens't include twofish, so tcpdump can't decode it.
#TCPDUMPFLAGS="-n -E twofish-cbc-hmac96:0xaaaabbbbccccdddd4043434545464649494a4a4c4c4f4f515152525454575758"
TCPDUMPFLAGS="-n "
INIT_SCRIPT=spi1.sh

PACKETRATE=100

