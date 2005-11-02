#!/bin/sh

TEST_TYPE=klipstest
TEST_PURPOSE=regress
TESTHOST=east
TESTNAME=east-des-parity-01
EXITONEMPTY=--exitonempty
SCRIPT=setkey.sh
REFCONSOLEOUTPUT=parityerror.txt
REFCONSOLEFIXUPS="kern-list-fixups.sed nocr.sed"
