#!/bin/bash

#
# $Id: repatch-console.sh,v 1.2 2002/10/16 21:59:47 mcr Exp $
#
# use this script to update the console reference output from the last
# run of tests, for a list of tests (directories) supplied on the
# command line, space delimited.  Start this from testing/klips, listing
# all the test names (directories), space-separated.

. ../utils/functions.sh
. setup.sh

console_edit_func() {
    testname=$1;           shift        
    consoleprefix=$1;  shift
    reffile=$1;        shift

    sed -f $FIXUPDIR/kern-list-fixups.sed $testname/$reffile >|$testname/$reffile.out
    mv $testname/$reffile.out $testname/$reffile
}

tests=`cat TESTLIST | sed -e '/^#/d' | while read type testname status; do echo $testname; done`
foreach_ref_console console_edit_func $tests

# $Log: repatch-console.sh,v $
# Revision 1.2  2002/10/16 21:59:47  mcr
# 	changes to console output to accomodate 2.4.19-uml12.
#
# Revision 1.1  2002/10/10 16:09:59  mcr
# 	refactored update-ref-console to use new foreach_ref_console
# 	function in functions.sh, added a simple way to invoke it,
# 	and also used it in repatch-console.sh.
#
# Revision 1.1  2002/09/20 17:05:18  rgb
# # This script is to update the console reference output from the last
# # run of tests, for a list of tests (directories) supplied on the
# # command line, space delimited.
#
#
