#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlXhost

TESTNAME=showhostkey-01
EXITONEMPTY=--exitonempty

XHOST_LIST="EAST"

REF_EAST_CONSOLE_OUTPUT=keys-console.txt
REF26_EAST_CONSOLE_OUTPUT=keys-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"

EASTHOST=east
EAST_INIT_SCRIPT=keys.sh


