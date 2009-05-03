#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=ctltest

TESTNAME=module-memory-01
TESTHOST=east

REF_CONSOLE_OUTPUT=examine-proc.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ls-date-fix.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS proc-mem-diff.pl"
INIT_SCRIPT=examine-proc.sh

# can only be used as a module
KLIPS_MODULE=-module            export KLIPS_MODULE

MOD_LOAD_ITERATIONS=5


