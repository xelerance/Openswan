#!/bin/bash

# show me
#set -x

# fail if any command fails
set -e

case $# in
    1) LIBRESWANSRCDIR=$1; shift;;
esac

if [ `id -u` = 0 ]
then
    echo Do not run this as root.
    exit
fi

#
# configuration for this file has moved to $LIBRESWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at umlsetup-sample.sh
# in this directory. Copy it to $LIBRESWANSRCDIR and edit it.
#
if [ -z "${LIBRESWANSRCDIR}" ] && [ -f umlsetup.sh ]
then
    LIBRESWANSRCDIR=`pwd`
fi

LIBRESWANSRCDIR=${LIBRESWANSRCDIR-../..}
if [ ! -f ${LIBRESWANSRCDIR}/umlsetup.sh ]
then
    echo >&2 "verify-uml.sh: Error: No umlsetup.sh configuration file in LIBRESWANSRCDIR=\"${LIBRESWANSRCDIR}\"."
    echo >&2 "    Please read instructions in doc/umltesting.html and testing/utils/umlsetup-sample.sh."
    exit 1
fi

. ${LIBRESWANSRCDIR}/umlsetup.sh

if [ ! -d ${KERNPOOL}/. ]; then echo Your KERNPOOL= is not properly set; exit 1; fi	

if [ "${UMLPATCH}" != "none" ] && [ ! -r ${UMLPATCH} ]; then echo Your UMLPATCH= is not properly set; exit 1; fi
if [ -z "${LIBRESWANHOSTS}" ]; then echo Your LIBRESWANHOSTS= is not properly set; exit 1; fi
if [ -z "${NATTPATCH}" ]; then echo Your NATTPATCH= is not properly set; exit 1; fi 
if [ ! -d ${BASICROOT}/. ]; then echo Your BASICROOT= is not properly set; exit 1; fi
    
#
# $Log: verify-uml.sh,v $
# Revision 1.2  2005/08/11 18:08:04  mikes
#     none is an acceptable answer for UMLPATCH
#
# Revision 1.1  2005/07/14 01:37:56  mcr
# 	script to check out umlsetup.sh and complain before
# 	we get too far.
#
#
#    
