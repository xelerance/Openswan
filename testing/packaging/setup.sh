
if [ -z "$FREESWANSRCDIR" ]
then
	if [ -f ../../Makefile.inc ]
	then
	  FREESWANSRCDIR=`cd ../.. && pwd`
	else 
	  if [ -f ../../../Makefile.inc ]
	  then 
	    FREESWANSRCDIR=`cd ../../.. && pwd`
	  fi
        fi  	
fi

if [ ! -f $FREESWANSRCDIR/Makefile.inc ]
then
	echo Umlsetup not found at FREESWANSRCDIR=$FREESWANSRCDIR.
	echo Is FREESWANSRCDIR set correctly'?'
	exit 5
fi

TESTINGROOT=${FREESWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`

REGRESSRESULTS=${REGRESSRESULTS-results}
MAKE_INSTALL_TEST_DEBUG=${MAKE_INSTALL_TEST_DEBUG-false}
RPM_INSTALL_TEST_DEBUG=${RPM_INSTALL_TEST_DEBUG-false}
FIXUPDIR=`cd ${FREESWANSRCDIR}/testing/packaging/fixups && pwd`

# kernel source for local UML, configured, against which one can
# build modules.
KERNEL_LINUSuml_SRC=${POOLSPACE}/plain${KERNVER} export KERNEL_LINUSUML_SRC


