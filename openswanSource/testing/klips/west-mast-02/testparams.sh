#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-mast-02
TESTHOST=west
EXITONEMPTY=--exitonempty

PRIVATE_ARPREPLY=true
PUB_INPUT=../inputs/02-sunrise-sunset-esp.pcap
REF_PRIV_OUTPUT=spi1-cleartext.txt
# THREEEIGHT=true

REF_CONSOLE_OUTPUT=mast1-console.txt
REF26_CONSOLE_OUTPUT=mast1-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"

INIT_SCRIPT=mast1in.sh
RUN_SCRIPT=mast1run.sh

#NETJIGDEBUG=true


