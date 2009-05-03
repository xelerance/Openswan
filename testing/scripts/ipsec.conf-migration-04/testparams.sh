#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=ctltest

TESTNAME=ipsec.conf-migration-04
TESTHOST=east

REF_CONSOLE_OUTPUT=east-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"

INIT_SCRIPT=ipsec.conf-migration_tests.sh
