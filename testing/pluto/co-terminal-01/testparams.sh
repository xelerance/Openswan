#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=umlXhost

TESTNAME=co-terminal-01
XHOST_LIST="NIC RW GWD MRCHARLIE"

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"

NICHOST=nic
NIC_INIT_SCRIPT=nic-init.sh

RWHOST=japan
RW_INIT_SCRIPT=rw-init.sh
RW_RUN_SCRIPT=rw-run.sh
RW_RUN2_SCRIPT=rw-run2.sh
REF_RW_CONSOLE_OUTPUT=rw-console.txt

GWDHOST=west
GWD_INIT_SCRIPT=gwd-init.sh
GWD_RUN_SCRIPT=gwd-run.sh
GWD_RUN2_SCRIPT=gwd-run2.sh
REF_GWD_CONSOLE_OUTPUT=gwd-console.txt

MRCHARLIEHOST=east
MRCHARLIE_RUN_SCRIPT=mrcharlie-init.sh
MRCHARLIE_RUN2_SCRIPT=rw-run2.sh
MRCHARLIE_FINAL_SCRIPT=mrcharlie-final.sh
REF_MRCHARLIE_CONSOLE_OUTPUT=mrcharlie-console.txt

ADDITIONAL_HOSTS="sunrise"



