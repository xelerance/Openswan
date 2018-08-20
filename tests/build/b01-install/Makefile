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
check:
	@mkdir -p ../OUTPUTS
	@rm -rf ${buildtmp}
	@mkdir -p ${buildtmp}
	env > ../OUTPUTS/env
	${MAKE} --no-print-directory -C ${OPENSWANSRCDIR} DESTDIR=${buildtmp} programs install
	(cd ${buildtmp} && find . -type f -print) | LC_ALL=C sort | tee ../OUTPUTS/01-build-list.raw | diff - 01-build-list.txt || cat ../OUTPUTS/01-build-list.raw
	${MAKE} --no-print-directory -C ${OPENSWANSRCDIR} DESTDIR=${buildtmp} programs install
	(cd ${buildtmp} && find . -type f -print) | LC_ALL=C sort | tee ../OUTPUTS/01-build-list-again.raw | diff - 01-build-list-again.txt || cat ../OUTPUTS/01-build-list-again.raw
	grep -v .old ../OUTPUTS/01-build-list-again.raw | diff - 01-build-list.txt

update:
	cp ../OUTPUTS/01-build-list.raw       01-build-list.txt
	cp ../OUTPUTS/01-build-list-again.raw 01-build-list-again.txt



