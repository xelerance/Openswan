#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=umlplutotest
TEST_GOAL_ITEM=204
TESTNAME=oe-snat-01


REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"

# a hack, we need two hosts, but they needn't be east/west.
EASTHOST=sunset
EAST_RUN_SCRIPT=sunsetrun.sh
REF_EAST_CONSOLE_OUTPUT=sunset-console.txt
REF26_EAST_CONSOLE_OUTPUT=sunset-console.txt

WESTHOST=west
WEST_INIT_SCRIPT=pass-init.sh
REF_WEST_CONSOLE_OUTPUT=west-console.txt
REF26_WEST_CONSOLE_OUTPUT=west-console.txt

ADDITIONAL_HOSTS="nic"

NETJIG_EXTRA=../basic-pluto-01/debugpublic.txt



