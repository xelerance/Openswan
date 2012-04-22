
if [ -z "$LIBRESWANSRCDIR" ]
then
	if [ -f ../../umlsetup.sh ]
	then
	  LIBRESWANSRCDIR=`cd ../.. && pwd`
	else 
	  if [ -f ../../../umlsetup.sh ]
	  then 
	    LIBRESWANSRCDIR=`cd ../../.. && pwd`
	  fi
        fi  	
fi

if [ ! -f $LIBRESWANSRCDIR/umlsetup.sh ]
then
	echo Umlsetup not found at LIBRESWANSRCDIR=$LIBRESWANSRCDIR.
	echo Is LIBRESWANSRCDIR set correctly'?'
	exit 5
fi

LIBRESWANSRCDIR=`cd ${LIBRESWANSRCDIR}; pwd`
export LIBRESWANSRCDIR

#eval `(cd $LIBRESWANSRCDIR && make env)`

TESTINGROOT=${LIBRESWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`
NJ=${UTILS}/uml_netjig/uml_netjig
KLIPSTOP=${LIBRESWANSRCDIR}/linux
FIXUPDIR=`cd ${LIBRESWANSRCDIR}/testing/klips/fixups && pwd`
CONSOLEDIFFDEBUG=${CONSOLEDIFFDEBUG-false}
NETJIGDEBUG=${NETJIGDEBUG-false}

# find this on the path if not already set.
TCPDUMP=${TCPDUMP-tcpdump}

REGRESSRESULTS=${REGRESSRESULTS-results}


