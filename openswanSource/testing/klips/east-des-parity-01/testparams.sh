#!/bin/sh

TEST_TYPE=klipstest
TEST_PURPOSE=regress
TESTHOST=east
TESTNAME=east-des-parity-01
EXITONEMPTY=--exitonempty
INIT_SCRIPT=setkey.sh
REF_CONSOLE_OUTPUT=parityerror.txt
REFCONSOLEFIXUPS="kern-list-fixups.sed nocr.sed"
