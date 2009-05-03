#!/bin/sh

TEST_PURPOSE=goal
TEST_GOAL_ITEM="pluto becomes aware of DNSSEC status"
TEST_TYPE=ctltest

TESTNAME=dns-key-01
TESTHOST=west
REF_CONSOLE_OUTPUT=dnskey.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-dig-sanitize.sed"

INIT_SCRIPT=dnskey1.sh

ADDITIONAL_HOSTS="nic"

# hack to avoid this test if we do not have USE_LWRES.
if [ "X${USE_LWRES}" != "Xtrue" ]
then
	testexpect="missing"
	echo USE_LWRES not set, skipping...
	exit 88
fi




