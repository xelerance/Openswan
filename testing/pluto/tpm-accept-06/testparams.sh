#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlplutotest

TESTNAME=tpm-accept-06
EASTHOST=east
WESTHOST=west

THREEEIGHT=true

REF_EAST_CONSOLE_OUTPUT=east-console.txt
REF26_EAST_CONSOLE_OUTPUT=east-console.txt
REF_WEST_CONSOLE_OUTPUT=west-console.txt
REF26_WEST_CONSOLE_OUTPUT=west-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-log-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tpm-log-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"

EAST_INIT_SCRIPT=eastinit.sh
WEST_INIT_SCRIPT=westinit.sh

# set up for stage 04a
EAST_RUN_SCRIPT=eastrun.sh

EAST_FINAL_SCRIPT=final.sh
WEST_FINAL_SCRIPT=final.sh

