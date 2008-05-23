#!/bin/sh

TEST_PURPOSE=goal
TEST_PROB_REPORT=0
TEST_TYPE=umlXhost

TESTNAME=mast-l2tp-04
XHOST_LIST="NIC NORTH EAST ROAD JAPAN WEST"

REF_EAST_CONSOLE_OUTPUT=east-console.txt
REF26_EAST_CONSOLE_OUTPUT=east-console.txt
REF_NORTH_CONSOLE_OUTPUT=north-console.txt
REF26_NORTH_CONSOLE_OUTPUT=north-console.txt
REF_NORTH_CONSOLE_OUTPUT=road-console.txt
REF26_NORTH_CONSOLE_OUTPUT=road-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS wilog.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pid-sanitize.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"

EASTHOST=east
EAST_INIT_SCRIPT=eastinit.sh
EAST_FINAL_SCRIPT=../nat-pluto-01/final.sh

NORTHHOST=north
NORTH_INIT_SCRIPT=../l2tp-01/northinit.sh
NORTH_RUN_SCRIPT=../l2tp-01/northrun.sh
NORTH_FINAL_SCRIPT=../l2tp-01/final.sh

ROADHOST=road
ROAD_INIT_SCRIPT=../l2tp-03/roadinit.sh
ROAD_RUN_SCRIPT=../l2tp-03/roadrun.sh
ROAD_FINAL_SCRIPT=../nat-pluto-01/final.sh

JAPANHOST=road
JAPAN_INIT_SCRIPT=japaninit.sh
JAPAN_RUN_SCRIPT=japanrun.sh
JAPAN_FINAL_SCRIPT=../nat-pluto-01/final.sh

NICHOST=nic
NIC_INIT_SCRIPT=../nat-pluto-01/nicinit.sh

WESTHOST=west
WEST_INIT_SCRIPT=westinit.sh

NETJIG_EXTRA=../basic-pluto-01/debugpublic.txt

