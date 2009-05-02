#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlplutotest

TESTNAME=food-groups-orderly-transition-01
EASTHOST=east
WESTHOST=west

REF_EAST_CONSOLE_OUTPUT=east-console.txt
REF_WEST_CONSOLE_OUTPUT=west-console.txt

REF_CONSOLE_FIXUPS="nocr.sed script-only.sed ipsec-setup-sanitize.sed pluto-log-sanitize.sed"

EAST_INIT_SCRIPT=eastinit.sh
EAST_RUN_SCRIPT=eastrun.sh

WEST_INIT_SCRIPT=westinit.sh

ADDITIONAL_HOSTS="sunset nic"
