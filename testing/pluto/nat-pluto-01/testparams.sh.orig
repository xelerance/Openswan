#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=umlXhost

TESTNAME=nat-pluto-01

XHOST_LIST="NIC NORTH EAST"

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-dig-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-lwdnsq-sanitize.pl"

EASTHOST=east
EAST_INIT_SCRIPT=eastinit.sh
EAST_FINAL_SCRIPT=eastfinal.sh
REF_EAST_CONSOLE_OUTPUT=east-console.txt

NORTHHOST=north
NORTH_INIT_SCRIPT=northinit.sh
NORTH_RUN_SCRIPT=northrun.sh
NORTH_FINAL_SCRIPT=northfinal.sh
REF_NORTH_CONSOLE_OUTPUT=north-console.txt

NICHOST=nic
NIC_INIT_SCRIPT=nicinit.sh

NETJIG_EXTRA=../basic-pluto-01/debugpublic.txt




