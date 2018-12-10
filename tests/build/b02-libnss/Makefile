# Makefile for the Openswan in-tree test cases
# Copyright (C) 2014 Michael Richardson <mcr@xelerance.com>
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

OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/build/01-build
buildtmp?=$(shell mkdir -p ../OUTPUTS/01-build; cd ../OUTPUTS/01-build; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc

# run the make install twice: the second time .old files get produced.
# note that unsets are required because this Makefile exported some variables to environment, and the Makefile.inc
# will not override environment variables.
check:
	@mkdir -p ../OUTPUTS
	@rm -rf ${OPENSWANSRCDIR}/OBJ.libnss.${BUILDENV}.${ARCH}
	@rm -rf ${OPENSWANSRCDIR}/OBJ.nolibnss.${BUILDENV}.${ARCH}
	@mkdir -p ${buildtmp}
	${MAKE} --no-print-directory n1
	${MAKE} --no-print-directory n2
	${MAKE} --no-print-directory n3

n1:
	${MAKE} --no-print-directory -C ${OPENSWANSRCDIR} DESTDIR=${buildtmp} OBJDIR=OBJ.nolibnss.${BUILDENV}.${ARCH} USE_LIBNSS=false programs install

n2:
	(cd ${OPENSWANSRCDIR} && unset OBJDIRTOP OBJDIR && ${MAKE} --no-print-directory USE_LIBNSS=true  DESTDIR=${buildtmp} programs install )

n3:
	unset OBJDIRTOP OBJDIR && ${MAKE} -C ${OPENSWANSRCDIR}/tests/functional/18-certloadorient USE_LIBNSS=true clean vars check


