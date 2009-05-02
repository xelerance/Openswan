#!/bin/sh

TEST_PURPOSE=goal
TEST_PROB_REPORT=0
TEST_TYPE=klipstest

TESTNAME=east-mast-03
TESTHOST=east
EXITONEMPTY=--exitonempty

THREEEIGHT=true
REF_PUB_OUTPUT=mast3-output.txt
REF_CONSOLE_OUTPUT=mast3-console.txt
REF26_CONSOLE_OUTPUT=mast3-console.txt

PUB_ARPREPLY=--arpreply

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758"
INIT_SCRIPT=mast3out.sh
RUN_SCRIPT=mast3run.sh

