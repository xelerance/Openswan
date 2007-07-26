#!/bin/sh

TEST_PURPOSE=goal
TEST_TYPE=umlplutotest

TESTNAME=algo-pluto-05
EASTHOST=east
WESTHOST=west

REF_EAST_CONSOLE_OUTPUT=east-console.txt
REF26_EAST_CONSOLE_OUTPUT=east-console.txt
REF_WEST_CONSOLE_OUTPUT=west-console.txt
REF26_WEST_CONSOLE_OUTPUT=west-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"

# set up east has both (3des,aes256 order)
EAST_INIT_SCRIPT=eastinit.sh

# set up west has both 
WEST_INIT_SCRIPT=westinit.sh

# init from west with both, 3des, and aes.
WEST_RUN_SCRIPT=westrun.sh

# change east to have just 3des
EAST_RUN2_SCRIPT=eastrun2.sh

# init from west with both
WEST_RUN2_SCRIPT=westrun2.sh

# change east to have just aes
EAST_RUN3_SCRIPT=eastrun3.sh

# init from west with both
WEST_RUN3_SCRIPT=westrun3.sh

# change east to have (aes256,3des)
EAST_RUN4_SCRIPT=eastrun4.sh

# init from west with both, 3des, and aes.
WEST_RUN4_SCRIPT=westrun4.sh


EAST_FINAL_SCRIPT=final.sh
WEST_FINAL_SCRIPT=final.sh





