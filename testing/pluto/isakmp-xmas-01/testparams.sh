#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=klipstest

TESTNAME=isakmp-xmas-01
TESTHOST=west
ARPREPLY=--arpreply

PUB_INPUT=../inputs/01-isakmp-xmas.pcap

REF_CONSOLE_OUTPUT=

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"

INIT_SCRIPT=startpluto.sh
FINAL_SCRIPT=dumpvarlogauth.sh



