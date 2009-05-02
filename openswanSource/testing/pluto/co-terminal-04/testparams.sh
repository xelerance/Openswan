#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=umlXhost

TESTNAME=co-terminal-04
XHOST_LIST="NIC JAPAN WEST EAST"

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-dig-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"

NICHOST=nic
NIC_INIT_SCRIPT=../co-terminal-02/nic-init.sh

JAPANHOST=japan
JAPAN_INIT_SCRIPT=japan-init.sh
JAPAN_RUN_SCRIPT=japan-run.sh
JAPAN_FINAL_SCRIPT=japan-final.sh
REF_JAPAN_CONSOLE_OUTPUT=japan-console.txt

WESTHOST=west
WEST_INIT_SCRIPT=../co-terminal-02/wavesec-init.sh
WEST_RUN2_SCRIPT=wavesec-run2.sh
REF_WEST_CONSOLE_OUTPUT=wavesec-console.txt

EASTHOST=east
EAST_INIT_SCRIPT=../co-terminal-02/east-init.sh
EAST_FINAL_SCRIPT=../co-terminal-02/east-final.sh
REF_EAST_CONSOLE_OUTPUT=east-console.txt

ADDITIONAL_HOSTS="sunrise"



