#!/bin/sh

BUILDTOP=${MYBOX-/c2/freeswan/freeswan-1.92}
export BUILDTOP
FREESWANSRCDIR=$BUILDTOP 
export FREESWANSRCDIR

. $BUILDTOP/umlsetup.sh

unset UML_public_CTL
unset UML_west_CTL
unset UML_east_CTL

expect -f $BUILDTOP/testing/utils/localswitches.tcl $*

