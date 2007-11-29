# Makefile for miscelaneous programs
# Copyright (C) 2002-2006  Michael Richardson	<mcr@xelerance.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.10 2005/07/27 20:32:19 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGRAM=_updown.netkey
PROGRAMDIR=${LIBDIR}

include ${srcdir}../Makefile.program

programs: ${PROGRAM}


ifeq ($(USE_IPROUTE2),false)
echo "Cannot build _updown.netkey without USE_IPROUTE2, aborted"
exit 1
else
UPDOWN_PROGRAM=_updown.ip2
endif

${PROGRAM}: ${UPDOWN_PROGRAM}
	cp ${UPDOWN_PROGRAM} ${PROGRAM}

cleanall::
	rm -f ${UPDOWN_PROGRAM} ${PROGRAM}


