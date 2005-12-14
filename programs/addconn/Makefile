# ipsec starter Makefile
# Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
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
# RCSID $Id: Makefile,v 1.15 2004/12/18 18:13:44 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGLIBS=${WHACKLIB} ${IPSECCONFLIB}

PROGRAM=addconn

# reach into pluto for now.
INCLUDES=-I${OPENSWANSRCDIR}/programs/pluto
INCLUDES+=-I${srcdir}

include ${srcdir}../Makefile.program

TAGS:	$(DISTSRC)
	LC_ALL=C etags $(ETAGSFLAGS) $(DISTSRC) $(LIBOPENSWANDIR)/*.[ch]

