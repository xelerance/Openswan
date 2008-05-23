# I really am not happy about using symlinks to make this work.
#
# I think that there should be a better way to do this.
# see module26.sh in packaging/makefiles
#

OPENSWANSRCDIR?=$(shell cd ../../..;pwd)

include ${OPENSWANSRCDIR}/Makefile.inc

TESTCASE=eroute01

include ${srcdir}../Makefile.pfkey

# 
# Local Variables: 
# compile-command: "make"
# End: 
