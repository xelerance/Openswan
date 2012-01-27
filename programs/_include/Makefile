# Makefile for miscelaneous programs
# Copyright (C) 2002  Michael Richardson	<mcr@freeswan.org>
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

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

$(info info: at .../programs/_include/Makefile OBJDIR="$(OBJDIR)" USE_OBJDIR="$(USE_OBJDIR)" MAKECMDGOALS="$(MAKECMDGOALS)" pwd:"$(shell pwd)")

PROGRAM=_include
PROGRAMDIR=${LIBDIR}

include ${srcdir}../Makefile.program
