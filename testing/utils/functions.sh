#!/bin/sh

#
# $Id: functions.sh,v 1.101 2003/11/25 00:22:53 mcr Exp $
#

preptest() {
    local testdir="$1"
    local testtype="$2"

    if [ ! -r "$testdir/testparams.sh" ]
    then
	echo '      ' "Missing configuration file: $testdir/testparams.sh"
	exit 1
    fi

    # make sure no results survive from a past run
    if [ ! -z "$testdir" ] ; then
	rm -rf "$testdir/OUTPUT"${KLIPS_MODULE}
	mkdir -p "$testdir/OUTPUT"${KLIPS_MODULE}
    fi

    cd $testdir

    source ./testparams.sh

    if [ "X$TEST_TYPE" != "X$testtype" ]
    then
        echo "Error: TEST_TYPE differs.  Check agreement of TESTLIST and testparams.sh"
	exit 1
    fi

    # get rid of any pluto core files.
    if [ -z "$XHOST_LIST" ]
    then
	XHOST_LIST="EAST WEST JAPAN"
    fi

    export XHOST_LIST

    # Xhost script takes things from the environment.
    for host in $XHOST_LIST
    do
	ROOT=$POOLSPACE/$host/root
	rm -f $ROOT/var/tmp/core
    done
}

lookforcore() {
    local testdir="$1"

    if [ -d "$testdir" ]
    then
	cd $testdir

	if [ -f ./testparams.sh ]
	then
	    source ./testparams.sh
	fi

	# get rid of any pluto core files.
	if [ -z "$XHOST_LIST" ]
	then
	    XHOST_LIST="EAST WEST JAPAN"
	fi

	export XHOST_LIST

	# Xhost script takes things from the environment.
	for host in $XHOST_LIST
	do
	    ROOT=$POOLSPACE/$host/root
	    if [ -f $ROOT/var/tmp/core ]
	    then
		mv $ROOT/var/tmp/core OUTPUT${KLIPS_MODULE}/pluto.$host.core
		echo "pluto.$host.core "
	    fi
	done
    fi
}


verboseecho() {
    if [ -n "${NETJIGVERBOSE}" ]
    then
	echo $@
    fi
}

# ??? NOTE:
# This seems to only sometimes set $success.
# Whatever interesting settings are made seem to be lost by the caller :-(
consolediff() {
    prefix=$1
    output=$2
    ref=$3

    cleanups="cat $output "

    for fixup in `echo $REF_CONSOLE_FIXUPS`
    do
	if [ -f $FIXUPDIR/$fixup ]
	then
	    case $fixup in
		*.sed) cleanups="$cleanups | sed -f $FIXUPDIR/$fixup";;
		*.pl)  cleanups="$cleanups | perl $FIXUPDIR/$fixup";;
		*.awk) cleanups="$cleanups | awk -f $FIXUPDIR/$fixup";;
		    *) echo Unknown fixup type: $fixup;;
            esac
	else
	    echo Fixup $fixup not found.
	    success="missing fixup"
	    return
        fi
    done

    fixedoutput=OUTPUT${KLIPS_MODULE}/${prefix}console-fixed.txt
    rm -f $fixedoutput OUTPUT${KLIPS_MODULE}/${prefix}console.diff
    $CONSOLEDIFFDEBUG && echo Cleanups is $cleanups
    eval $cleanups >$fixedoutput

    # stick terminating newline in for fun.
    echo >>$fixedoutput

    if diff -N -u -w -b -B $ref $fixedoutput >OUTPUT${KLIPS_MODULE}/${prefix}console.diff
    then
	echo "${prefix}Console output matched"
    else
	echo "${prefix}Console output differed"

	case "$success" in
	true)	failnum=2 ;;
	esac

	success=false
    fi
}

compat_variables() {
    if [ -z "$REF_CONSOLE_OUTPUT" ] && [ -n "$REFCONSOLEOUTPUT" ]
    then
	REF_CONSOLE_OUTPUT=$REFCONSOLEOUTPUT
    fi

    if [ -z "$REF_CONSOLE_FIXUPS" ] && [ -n "$REFCONSOLEFIXUPS" ]
    then
	REF_CONSOLE_FIXUPS=$REFCONSOLEFIXUPS
    fi

    if [ -z "$REF_PUB_OUTPUT" ] && [ -n "$REFPUBOUTPUT" ]
    then
	REF_PUB_OUTPUT=$REFPUBOUTPUT
    fi

    if [ -z "$REF_PRIV_OUTPUT" ] && [ -n "$REFPRIVOUTPUT" ]
    then
	REF_PRIV_OUTPUT=$REFPRIVOUTPUT
    fi

    if [ -z "$PRIV_INPUT" ] && [ -n "$PRIVINPUT" ]
    then
	PRIV_INPUT=$PRIVINPUT
    fi

    if [ -z "$PUB_INPUT" ] && [ -n "$PUBINPUT" ]
    then
	PUB_INPUT=$PUBINPUT
    fi

    if [ -z "$INIT_SCRIPT" ] && [ -n "$SCRIPT" ]
    then
	INIT_SCRIPT=$SCRIPT
    fi

    if [ -z "$EAST_RUN_SCRIPT" ] && [ -n "$RUN_EAST_SCRIPT" ]
    then
	EAST_RUN_SCRIPT=$RUN_EAST_SCRIPT
    fi
    if [ -z "$WEST_RUN_SCRIPT" ] && [ -n "$RUN_WEST_SCRIPT" ]
    then
	WEST_RUN_SCRIPT=$RUN_WEST_SCRIPT
    fi

    if [ -z "$EAST_FINAL_SCRIPT" ] && [ -n "$FINAL_EAST_SCRIPT" ]
    then
	EAST_FINAL_SCRIPT=$FINAL_EAST_SCRIPT
    fi
    if [ -z "$WEST_FINAL_SCRIPT" ] && [ -n "$FINAL_WEST_SCRIPT" ]
    then
	WEST_FINAL_SCRIPT=$FINAL_WEST_SCRIPT
    fi
}

# this is called to set additional variables that depend upon testparams.sh
prerunsetup() {
    if [ -n "$KLIPS_MODULE" ]
    then
	HOST_START=$POOLSPACE/$TESTHOST/startmodule.sh
	EAST_START=$POOLSPACE/$EASTHOST/startmodule.sh
	WEST_START=$POOLSPACE/$WESTHOST/startmodule.sh
	REPORT_NAME=${TESTNAME}${KLIPS_MODULE}
    else
	HOST_START=$POOLSPACE/$TESTHOST/start.sh
	EAST_START=$POOLSPACE/$EASTHOST/start.sh
	WEST_START=$POOLSPACE/$WESTHOST/start.sh
	REPORT_NAME=${TESTNAME}
    fi

    compat_variables;

    # export variables that are common.
    export PACKETRATE
}


setup_additional_hosts() {

    if [ -n "${ADDITIONAL_HOSTS}" ]
    then
        SEP=""
	HOSTLIST=""
	for host in ${ADDITIONAL_HOSTS}
	do
	    HOSTLIST="${HOSTLIST}${SEP}${host}=${POOLSPACE}/${host}/start.sh"
	    SEP=","
	done

	echo "-H ${HOSTLIST}"
    fi
}


#
# use this function to run some script on each reference output script.
#
# Start this from testing/*, listing all the test names (directories),
# space-separated. The script to run is the first argument.
#
# The script will be provided with three arguments -
#    1) the name of the test
#    2) the name of the console# which is either "", east or west
#    3) and the file where the reference console should be placed.
#
# The current working directory is *NOT* changed before the script is ran.
#
foreach_ref_console() {
    script=$1
    shift

    for i in $*
    do
	    echo $i:
	    if [ -d $i ]
	    then
		    (if [ -f $i/testparams.sh ]
		    then
			    . $i/testparams.sh
			    compat_variables;
			    if [ -n "$REF_CONSOLE_OUTPUT" ]
			    then
				echo $script $i "" $REF_CONSOLE_OUTPUT
				$script $i "" $REF_CONSOLE_OUTPUT
			    fi
			    if [ -n "$REF_EAST_CONSOLE_OUTPUT" ]
			    then
				echo $script $i east $REF_EAST_CONSOLE_OUTPUT
				$script $i east $REF_EAST_CONSOLE_OUTPUT
			    fi
			    if [ -n "$REF_WEST_CONSOLE_OUTPUT" ]
			    then
				echo $script $i west $REF_WEST_CONSOLE_OUTPUT
				$script $i west $REF_WEST_CONSOLE_OUTPUT
			    fi
		    fi)
	    fi
    done
}

roguekill() {
    REPORT_NAME="$1"
    local rogue_sighted=""

    if [ -n "$REGRESSRESULTS" ]
    then
	rm -f $REGRESSRESULTS/$REPORT_NAME/roguelist.txt
	mkdir -p $REGRESSRESULTS/$REPORT_NAME
    fi

    # search for rogue UML
    local pointless=false
    local firstpass=true
    local other_rogues=""
    verboseecho "UML_BRAND=$UML_BRAND"
    for sig in KILL CONT KILL CONT KILL CONT KILL
    do
	if $pointless
	then
	    break;
	fi
	pointless=true
	for i in `grep -s -l '^'"$POOLSPACE"'/[a-z]*/linux\>' /proc/[1-9]*/cmdline`
	do
	    local pdir=`dirname "$i"`
	    local badpid=`basename $pdir`
	    if [ ! -r $pdir/environ ] || strings $pdir/environ | grep "^UML_BRAND=$UML_BRAND"'$' >/dev/null
	    then
		echo "${sig}ING ROGUE UML: $badpid `tr '\000' ' ' <$pdir/cmdline`"
		if [ -n "$REGRESSRESULTS" ]
		then
		   echo "UML pid $pdir went ROGUE" >>$REGRESSRESULTS/$REPORT_NAME/roguelist.txt
		fi

		# the cwd is a good indication of what test was being executed.
		rogue_sighted=" rogue"
		pointless=false
		ls -l $pdir/cwd
		kill -$sig $badpid
	    elif $firstpass
	    then
		other_rogues="$other_rogues $badpid"
	    fi
	done
	# might take some realtime for a kill to work
	if ! $pointless
	then
	    sleep 2
	fi
	firstpass=false
    done
    if [ -n "$other_rogues" ]
    then
	echo "ROGUES without brand $UML_BRAND:"
	ps -f -p -w $other_rogues
    fi
    stat="$stat$rogue_sighted"
}

#
# record results records the status of each test in
#   $REGRESSRESULTS/$REPORT_NAME/status
#
# If the status is negative, then the "OUTPUT${KLIPS_MODULE}" directory of the test is
# copied to $REGRESSRESULTS/$REPORT_NAME/OUTPUT${KLIPS_MODULE} as well.
#
# The file $testname/description.txt if it exists is copied as well.
#
# If $REGRESSRESULTS is not set, then nothing is done.
#
# See testing/utils/regress-summarizeresults.pl for a tool to build a nice
# report from these files.
#
# See testing/utils/regress-nightly.sh and regress-stage2.sh for code
# that sets up $REGRESSRESULTS.
#
# usage: recordresults testname testtype status REPORTNAME
#
recordresults() {
    local testname="$1"
    local testexpect="$2"
    local status="$3"
    local REPORT_NAME="$4"

    export REGRESSRESULTS
    roguekill $REPORT_NAME

    if [ -n "$REGRESSRESULTS" ]
    then
	rm -rf $REGRESSRESULTS/$REPORT_NAME
	mkdir -p $REGRESSRESULTS/$REPORT_NAME
	console=false
	packet=false

	# if there was a core file, add that to status
	cores=`( lookforcore $testname )`
	if [ ! -z "$cores" ]
	then
	    status="$status core"
	fi

	# if there was a rogue, add that to status
	if [ -f $REGRESSRESULTS/$REPORT_NAME/status/roguelist.txt ]
	then
	    status="$status rogue"
	fi

	# note that 0/1 is shell sense.
	case "$status" in
	    0) success=true;;
	    1) success=false; console=true;;
	    2) success=false; console=false; packet=true;;
	    99) success="missing 99"; console=false; packet=false;;
	    true)  success=true;;
	    false) sucesss=false;;
	    succeed) success=true;;
	    fail)  success=false;;
	    yes)   success=true;;
	    no)    success=false;;
	    skipped) success=skipped;;
	    missing) success=missing;;
	    *)	success=false;;
	esac

	echo "Recording "'"'"$success: $status"'"'" to $REGRESSRESULTS/$REPORT_NAME/status"
	echo "$success: $status" >$REGRESSRESULTS/$REPORT_NAME/status
	echo console=$console >>$REGRESSRESULTS/$REPORT_NAME/status
	echo packet=$packet   >>$REGRESSRESULTS/$REPORT_NAME/status

	echo "$testexpect" >$REGRESSRESULTS/$REPORT_NAME/expected

	if [ -f $testname/description.txt ]
	then
	    cp $testname/description.txt $REGRESSRESULTS/$REPORT_NAME
	fi


	# the following is in a subprocess to protect against certain
	# testparams.sh which exit!
	(
	    if [ -r "$testdir/testparams.sh" ]
	    then
		. "$testdir/testparams.sh"
	    fi

	    case "${TEST_PURPOSE}" in
	    regress) echo ${TEST_PROB_REPORT} >$REGRESSRESULTS/$REPORT_NAME/regress.txt;;
	       goal) echo ${TEST_GOAL_ITEM}   >$REGRESSRESULTS/$REPORT_NAME/goal.txt;;
	    exploit) echo ${TEST_EXPLOIT_URL} >$REGRESSRESULTS/$REPORT_NAME/exploit.txt;;
		  *) echo "unknown TEST_PURPOSE (${TEST_PURPOSE})" ;;
	    esac
	)

	case "$success" in
	false)
	    # ???? why the heck is this code run only when $success is false?
	    # NOTE: ${KLIPS_MODULE} is part of $REPORT_NAME
	    rm -rf $REGRESSRESULTS/$REPORT_NAME/OUTPUT
	    mkdir -p $REGRESSRESULTS/$REPORT_NAME/OUTPUT
	    tar -C $testname/OUTPUT${KLIPS_MODULE} -c -f - . | (cd $REGRESSRESULTS/$REPORT_NAME/OUTPUT && tar xf - )
	    ;;
	esac
    fi

    case "$status" in
    0)	echo '*******  PASSED '$REPORT_NAME' ********' ;;
    skipped)  echo '*******  SKIPPED '$REPORT_NAME' ********' ;;
    *)  echo '*******  FAILED '$REPORT_NAME' ********' ;;
    esac
}

#
#    pcap_filter west   $REF_OUTPUT $WESTOUTPUT $REF_WEST_FILTER
#
pcap_filter() {

    HOST=
    OUTPUT=
    FILTER=
    REF_OUTPUT=

    #echo PCAP_FILTER $@
    HOST=$1
    REF_OUTPUT=$2
    OUTPUT=$3
    FILTER=$4

    if [ -z "$FILTER" ]
    then
	FILTER=cat
    fi

    FILTER="$FILTER | sed -f $FIXUPDIR/tcpdump-three-eight.sed"

    if [ -n "$OUTPUT" ]
    then
	rm -f OUTPUT${KLIPS_MODULE}/${OUTPUT}.txt
	verboseecho $TCPDUMP -t $TCPDUMPFLAGS '|' "$FILTER" '>' OUTPUT${KLIPS_MODULE}/${OUTPUT}.txt
	eval "$TCPDUMP -t $TCPDUMPFLAGS -r OUTPUT${KLIPS_MODULE}/$OUTPUT.pcap | $FILTER >|OUTPUT${KLIPS_MODULE}/$OUTPUT.txt"

	rm -f OUTPUT${KLIPS_MODULE}/$OUTPUT.diff
	if diff -u -w -b -B $REF_OUTPUT OUTPUT${KLIPS_MODULE}/$OUTPUT.txt >OUTPUT${KLIPS_MODULE}/$OUTPUT.diff
	then
	    printf "%-8s side output matched\n" $HOST
	else
	    printf "%-8s side output differed\n" $HOST
	    success=false
	fi
    fi
}



# netjigtest - invoke a single UML with input/output setup for KLIPS
#              testing.
#
# variables are documented in doc/makecheck.html
#
netjigtest() {

    prerunsetup

    success=true
    failnum=1

    PRIVOUTPUT=''
    PUBOUTPUT=''

    NJARGS=''

    if [ -n "$PRIV_INPUT" ]
    then
	NJARGS="$NJARGS -p $PRIV_INPUT"
    fi

    if [ -n "$PUB_INPUT" ]
    then
	NJARGS="$NJARGS -P $PUB_INPUT"
    fi

    if [ -n "$REF_CONSOLE_OUTPUT" ]
    then
	NJARGS="$NJARGS -c OUTPUT${KLIPS_MODULE}/console.txt"
    fi

    if [ -n "$REF_PRIV_OUTPUT" ]
    then
	PRIVOUTPUT=`basename $REF_PRIV_OUTPUT .txt `
	NJARGS="$NJARGS -r OUTPUT${KLIPS_MODULE}/$PRIVOUTPUT.pcap"
    fi

    if [ -n "$REF_PUB_OUTPUT" ]
    then
	PUBOUTPUT=`basename $REF_PUB_OUTPUT .txt`
	NJARGS="$NJARGS -R OUTPUT${KLIPS_MODULE}/$PUBOUTPUT.pcap"
    fi

    if [ -n "$NETJIGARGS" ]
    then
	NJARGS="$NJARGS $NETJIGARGS"
    fi

    if [ "X$ARPREPLY" = "X--arpreply" ]
    then
	NJARGS="$NJARGS -a"
    fi

    if [ -n "${RUN_SCRIPT}" ]
    then
	NJARGS="$NJARGS -s ${RUN_SCRIPT}"
    fi

    if [ -n "${FINAL_SCRIPT}" ]
    then
	NJARGS="$NJARGS -I ${FINAL_SCRIPT}"
    fi

    NJARGS="$NJARGS "`setup_additional_hosts`

#    if [ "X$EXITONEMPTY" = "X--exitonempty" ]
#    then
#	NJARGS="$NJARGS -a"
#    fi

    rm -f OUTPUT${KLIPS_MODULE}/console.txt

    cmd="expect -f $UTILS/host-test.tcl -- -U $TESTHOST -u $HOST_START -i ${INIT_SCRIPT} -n $NJ $NJARGS"
    $NETJIGDEBUG && echo $cmd
    eval $cmd

    #uml_mconsole $TESTHOST halt

    pcap_filter private "$REF_PRIV_OUTPUT" "$PRIVOUTPUT" "$REF_PRIV_FILTER"
    pcap_filter public  "$REF_PUB_OUTPUT"  "$PUBOUTPUT"  "$REF_PUB_FILTER"

    if [ -n "$REF_CONSOLE_OUTPUT" ]
    then
	consolediff "" OUTPUT${KLIPS_MODULE}/console.txt $REF_CONSOLE_OUTPUT
    fi

    case "$success" in
    true)	exit 0 ;;
    *)		exit $failnum ;;
    esac
}

###################################
#
#  test type: klipstest
#
###################################

# test entry point:
klipstest() {
    testdir=$1
    testexpect=$2

    echo '*******  KLIPS RUNNING' $testdir${KLIPS_MODULE} '*******'

    export UML_BRAND="$$"
    ( preptest $testdir klipstest && netjigtest )
    stat=$?

    recordresults $testdir "$testexpect" "$stat" $testdir${KLIPS_MODULE}
}

###################################
#
#  test type: ctltest - run the UML with no I/O
#
###################################

do_ctl_test() {
    success=true

    prerunsetup

    NJARGS=""

    if [ -n "${FINAL_SCRIPT}" ]
    then
	NJARGS="$NJARGS -I ${FINAL_SCRIPT}"
    fi

    if [ -n "$REF_CONSOLE_OUTPUT" ]
    then
	rm -f OUTPUT${KLIPS_MODULE}/console.txt
	NJARGS="$NJARGS -c OUTPUT${KLIPS_MODULE}/console.txt"
    fi

    if [ "X${NEEDS_DNS}" = "Xtrue" ]
    then
	NJARGS="$NJARGS -D $POOLSPACE/nic/start.sh"
    fi

    NJARGS="$NJARGS "`setup_additional_hosts`

    cmd="expect -f $UTILS/host-test.tcl -- -U $TESTHOST -u $HOST_START -i ${INIT_SCRIPT} -n $NJ $NJARGS"
    $NETJIGDEBUG && echo $cmd
    eval $cmd


    if [ -n "$REF_CONSOLE_OUTPUT" ]
    then
	consolediff "" OUTPUT${KLIPS_MODULE}/console.txt $REF_CONSOLE_OUTPUT
    fi

    case "$success" in
    true)	exit 0 ;;
    *)		exit 2 ;;
    esac
}


# test entry point:
ctltest() {
    testdir=$1
    testexpect=$2

    echo '****** CONTROL RUNNING' $testdir${KLIPS_MODULE} '*******'

    export UML_BRAND="$$"
    ( preptest $testdir ctltest && do_ctl_test )
    stat=$?

    recordresults $testdir "$testexpect" "$stat" $testdir${KLIPS_MODULE}
}

skiptest() {
    testdir=$1
    testexpect=$2

    export TEST_PURPOSE=regress

    UML_BRAND=0 recordresults $testdir "$testexpect" skipped $testdir${KLIPS_MODULE}
}

###################################
#
#  test type: mkinsttest
#
###################################

do_make_install_test() {

    rm -rf OUTPUT${KLIPS_MODULE}/root
    mkdir -p OUTPUT${KLIPS_MODULE}/root

    # locale affects sort order.
    LC_ALL=C export LC_ALL

    success=true
    instdir=`cd OUTPUT${KLIPS_MODULE}/root && pwd`

    prerunsetup

    if [ -n "$INSTALL_FLAGS" ]
    then
	$MAKE_INSTALL_TEST_DEBUG && echo make --no-print-directory DESTDIR=$instdir $INSTALL_FLAGS
	(cd $FREESWANSRCDIR && eval make FREESWANSRCDIR=`pwd` --no-print-directory DESTDIR=$instdir $INSTALL_FLAGS ) >OUTPUT${KLIPS_MODULE}/install1.txt 2>&1 || exit 1
    fi

    if [ -n "$POSTINSTALL_SCRIPT" ]
    then
	$POSTINSTALL_SCRIPT $FREESWANSRCDIR $instdir || exit 1
    fi

    if [ -n "$INSTALL2_FLAGS" ]
    then
	$MAKE_INSTALL_TEST_DEBUG && echo make --no-print-directory DESTDIR=$instdir $INSTALL2_FLAGS
	(cd $FREESWANSRCDIR && eval make FREESWANSRCDIR=`pwd` --no-print-directory DESTDIR=$instdir $INSTALL2_FLAGS ) >OUTPUT${KLIPS_MODULE}/install2.txt 2>&1 || exit 1
    fi

    if [ -n "$UNINSTALL_FLAGS" ]
    then
	$MAKE_INSTALL_TEST_DEBUG && echo make --no-print-directory DESTDIR=$instdir $UNINSTALL_FLAGS
	(cd $FREESWANSRCDIR && eval make FREESWANSRCDIR=`pwd` --no-print-directory DESTDIR=$instdir $UNINSTALL_FLAGS ) >OUTPUT${KLIPS_MODULE}/uninstall.txt 2>&1 || exit 1
    fi

    if [ -n "$REF_MAKE_DOC_OUTPUT" ]
    then
      rm -f OUTPUT${KLIPS_MODULE}/$REF_MAKE_DOC_OUTPUT.txt

      (cd $FREESWANSRCDIR/doc && eval make FREESWANSRCDIR=$FREESWANSRCDIR clean --no-print-directory && eval make FREESWANSRCDIR=$FREESWANSRCDIR --no-print-directory ) | sort >OUTPUT${KLIPS_MODULE}/$REF_MAKE_DOC_OUTPUT.txt
      if diff -u -w -b -B $REF_MAKE_DOC_OUTPUT.txt OUTPUT${KLIPS_MODULE}/$REF_MAKE_DOC_OUTPUT.txt >OUTPUT${KLIPS_MODULE}/$REF_MAKE_DOC_OUTPUT.diff
      then
	 echo "make doc output matched"
      else
	 echo "make doc output differed"
	 success=false
      fi
    fi

    if [ -n "$REF_FIND_f_l_OUTPUT" ]
    then
      rm -f OUTPUT${KLIPS_MODULE}/$REF_FIND_f_l_OUTPUT

      (cd OUTPUT${KLIPS_MODULE}/root && find . \( -type f -or -type l \) -print ) | sort >OUTPUT${KLIPS_MODULE}/$REF_FIND_f_l_OUTPUT.txt
      if diff -u -w -b -B $REF_FIND_f_l_OUTPUT.txt OUTPUT${KLIPS_MODULE}/$REF_FIND_f_l_OUTPUT.txt >OUTPUT${KLIPS_MODULE}/$REF_FIND_f_l_OUTPUT.diff
      then
	 echo "Install list file list matched"
      else
	 echo "Install list file list differed"
	 success=false
      fi
    fi


    if [ -n "$REF_FILE_CONTENTS" ]
    then
      cat $REF_FILE_CONTENTS | while read reffile samplefile
      do
	if diff -u -w -b -B $reffile $instdir/$samplefile >OUTPUT${KLIPS_MODULE}/$reffile.diff
	then
	    echo "Reffile $samplefile matched"
	else
	    echo "Reffile $samplefile differed"
	    success=false
	fi
      done
    fi

    case "$success" in
    true)	exit 0 ;;
    *)		exit 1 ;;
    esac
}


# test entry point:
mkinsttest() {
    testdir=$1
    testexpect=$2

    echo '**** Make Install RUNNING' $testdir${KLIPS_MODULE} '****'

    FREESWANSRCDIR=`cd $FREESWANSRCDIR && pwd` export FREESWANSRCDIR

    export UML_BRAND="$$"
    ( preptest $testdir mkinsttest && do_make_install_test )
    stat=$?

    recordresults $testdir "$testexpect" "$stat" $testdir${KLIPS_MODULE}
}

###################################
#
#  test type: rpm_build_install_test
#
###################################

do_rpm_install_test() {

    rm -rf OUTPUT${KLIPS_MODULE}/root
    mkdir -p OUTPUT${KLIPS_MODULE}/root

    success=true
    instdir=`cd OUTPUT${KLIPS_MODULE}/root && pwd`

    prerunsetup

    RPM_KERNEL_SOURCE=`eval echo $RPM_KERNEL_SOURCE`
    if [ -z "$RPM_KERNEL_SOURCE" ]
    then
	echo "Test must define \$RPM_KERNEL_SOURCE ($RPM_KERNEL_SOURCE)"
	success='missing $RPM_KERNEL_SOURCE'
	exit 99
    fi

    if [ -z "$RPM_OMIT_BUILD" ]
    then
	echo "Building with kernel source $RPM_KERNEL_SOURCE";

	(cd $FREESWANSRCDIR/packaging/redhat && make clean --no-print-directory && make --no-print-directory RH_KERNELSRC=$RPM_KERNEL_SOURCE FREESWANSRCDIR=$FREESWANSRCDIR rpm )
    fi

    mkdir OUTPUT${KLIPS_MODULE}/rpm
    cp $FREESWANSRCDIR/packaging/redhat/rpms/RPMS/i386/*.rpm OUTPUT${KLIPS_MODULE}/rpm

    # while loop below winds up in sub-shell. Argh.
    successfile=OUTPUT${KLIPS_MODULE}/success
    echo "$success" >$successfile

    if [ -n "$REF_RPM_CONTENTS" ]
    then
      cat $REF_RPM_CONTENTS | while read rpmfile rpmcontents
      do
        if [ -z "$rpmfile" ]
	then
	    continue;
	fi
        # expand $rpmfile, which may have wildcards!
	realfile=`eval echo OUTPUT${KLIPS_MODULE}/rpm/${rpmfile}`
	if [ ! -f $realfile ]
	then
	    echo "RPM production failed to build anything to match $rpmfile"
	    echo false >$successfile
	fi
        rpm2cpio $realfile | cpio -it >OUTPUT${KLIPS_MODULE}/$rpmcontents.txt
	if diff -u -w -b -B $rpmcontents.txt OUTPUT${KLIPS_MODULE}/$rpmcontents.txt >OUTPUT${KLIPS_MODULE}/$rpmcontents.diff
	then
	    echo "Reffile ($rpmcontents) for $realfile matched"
	else
	    echo "Reffile ($rpmcontents) for $realfile differed"
	    echo false >$successfile
	fi
      done
    fi

    success=`cat $successfile`

    case "$success" in
    true)	exit 0 ;;
    *)		exit 1 ;;
    esac
}


# test entry point:
rpm_build_install_test() {
    testdir=$1
    testexpect=$2

    echo '**** Make Install RUNNING' $testdir${KLIPS_MODULE} '****'

    FREESWANSRCDIR=`cd $FREESWANSRCDIR && pwd` export FREESWANSRCDIR

    export UML_BRAND="$$"
    ( preptest $testdir rpm_build_install_test && do_rpm_install_test )
    stat=$?
    if [ $stat = 99 ]
    then
        echo Test missing parts.
	stat='missing parts'
    fi

    recordresults $testdir "$testexpect" "$stat" $testdir${KLIPS_MODULE}
}

###################################
#
#  test type: libtest
#
###################################

# test entry point:
libtest() {
    testobj=$1
    testexpect=$2
    testsrc=$testobj.c

    echo '**** make libtest RUNNING' $testsrc '****'

    symbol=`echo $testobj | tr 'a-z' 'A-Z'`_MAIN

    cc -g -o $testobj -D$symbol -I${LIBFREESWANDIR} -I${FREESWANSRCDIR}/linux/include -I${FREESWANSRCDIR} ${LIBFREESWANDIR}/$testsrc ${FREESWANLIB}
    rm -rf lib-$testobj/OUTPUT
    mkdir -p lib-$testobj/OUTPUT

    export TEST_PURPOSE=regress

    ( ./$testobj -r >lib-$testobj/OUTPUT${KLIPS_MODULE}/$testobj.txt )

    stat=$?
    if [ $stat -gt 128 ]
    then
	stat="$stat core"
    fi

    TEST_PURPOSE=regress  UML_BRAND=0 recordresults lib-$testobj "$testexpect" $stat lib-$testobj
}

###################################
#
#  test type: umlplutotest
#
###################################

#  If set, then the public and private packet output will be captured,
#  turned into ASCII with tcpdump, and diff'ed against these files.
#    REF_PUB_OUTPUT    - for public side
#    REF_EAST_OUTPUT   - for east private side
#    REF_WEST_OUTPUT   - for west private side
#    TCPDUMPARGS     - extra args for TCPDUMP.
#
#  If set, then the console output will be diff'ed against this file:
#    REF_EAST_CONSOLE_OUTPUT
#    REF_WEST_CONSOLE_OUTPUT
#
#  The console output may need to be sanitized. The list of fixups from
# REF_CONSOLE_FIXUPS will be appled from "fixups". The extension is used to
# determine what program to use.
#
#  Some additional options to control the network emulator
#    ARPREPLY=--arpreply         - if ARPs should be answered

# test entry point:
umlplutotest() {
    testdir=$1
    testexpect=$2

    echo '***** UML PLUTO RUNNING' $testdir${KLIPS_MODULE} '*******'

    export UML_BRAND="$$"
    ( export XHOST_LIST="EAST WEST"
      preptest $testdir umlplutotest && do_umlX_test )
    stat=$?

    recordresults $testdir "$testexpect" "$stat" $testdir${KLIPS_MODULE}
}

###################################
#
#  test type: kernel_patch_test
#
###################################
do_kernel_patch_test() {
    success=true

    set -e

    if [ -z "${KERNEL_VERSION}" ]
    then
	exit 0;
    fi

    if [ -z "${KERNEL_NAME}" ]
    then
        echo Kernel name not defined.
	exit 99
    fi

    kernelver=`echo ${KERNEL_VERSION} | tr '.' '_'`
    kernelname=`echo ${KERNEL_NAME} | tr 'a-z' 'A-Z'`

    kernel_var_name=KERNEL_${kernelname}${kernelver}_SRC
    echo Looking for kernel source ${kernel_var_name}
    KERNEL_SRC=${!kernel_var_name}

    echo at location ${KERNEL_SRC}.

    if [ -z "${KERNEL_SRC}" ] || [ ! -d "${KERNEL_SRC}" ]
    then
	echo Kernel source not found.
	exit 99
    fi

    # okay, we got some source code to play with!
    mkdir OUTPUT${KLIPS_MODULE}/$kernel_var_name

    # get ourselves a kernel source tree.
    if (cd OUTPUT${KLIPS_MODULE}/$kernel_var_name && lndir -silent $KERNEL_SRC . )
    then
	:
    else
        echo Unable to link in kernel source.
	exit 99
    fi

    env >OUTPUT${KLIPS_MODULE}/env.txt

    # now patch it. (set +x turns off any debugging there might have been)
    set -x
    set -v
    # the environment variable FREESWANSRCDIR should be correct
    # but the make macro FREESWANSRCDIR may be relative, and hence wrong
    (cd ${FREESWANSRCDIR} && make FREESWANSRCDIR=`pwd` kernelpatch${KERNEL_VERSION} ) | tee OUTPUT${KLIPS_MODULE}/patchfile.patch | (cd OUTPUT${KLIPS_MODULE}/$kernel_var_name && patch -p1 2>&1 ) >OUTPUT${KLIPS_MODULE}/patch-output.txt

    # compare the patch.
    if [ -n "${REF_PATCH_OUTPUT}" ]
    then
        consolediff "" OUTPUT${KLIPS_MODULE}/patch-output.txt $REF_PATCH_OUTPUT
    fi

    # normally, clean up the kernel output, as it is volumnous
    if [ -z "${KERNEL_PATCH_LEAVE_SOURCE}" ]
    then
      rm -rf OUTPUT${KLIPS_MODULE}/$kernel_var_name
    fi

    case "$success" in
    true)	exit 0 ;;
    *)		exit 1 ;;
    esac
}

# test entry point:
kernel_patch_test() {
    testdir=$1
    testexpect=$2

    echo '***** KERNEL PATCH RUNNING' $testdir '*******'

    export UML_BRAND="$$"
    ( preptest $testdir kernel_patch_test && do_kernel_patch_test )
    stat=$?
    if [ $stat = 99 ]
    then
        echo Test missing parts.
	stat='missing parts'
    fi

    recordresults $testdir "$testexpect" "$stat" $testdir
}

###################################
#
#  test type: module_compile
#
###################################

do_module_compile_test() {

    rm -rf OUTPUT${KLIPS_MODULE}/module
    mkdir -p OUTPUT${KLIPS_MODULE}/module
    set -e

    success=false
    moddir=`cd OUTPUT${KLIPS_MODULE}/module && pwd`

    prerunsetup

    if [ -z "${KERNEL_VERSION}" ]
    then
	exit 0;
    fi

    if [ -z "${KERNEL_NAME}" ]
    then
        echo Kernel name not defined.
	exit 99
    fi

    kernelver=`echo ${KERNEL_VERSION} | tr '.' '_'`
    kernelname=`echo ${KERNEL_NAME} | tr 'a-z' 'A-Z'`

    kernel_var_name=KERNEL_${kernelname}${kernelver}_SRC
    echo Looking for kernel source ${kernel_var_name}
    KERNEL_SRC=${!kernel_var_name}

    if [ -z "${KERNEL_SRC}" ]
    then
        echo Kernel source missing.
	exit 99
    fi

    if [ ! -r ${MODULE_DEF_INCLUDE} ]
    then
	echo the file ${MODULE_DEF_INCLUDE} is needed to build this test.
	exit 99
    fi

    if [ ! -r ${MODULE_DEFCONFIG} ]
    then
	echo the file ${MODULE_DEFCONFIG} is needed to build this test.
	exit 99
    fi

    if [ -z "${ARCH}" ]
    then
	ARCH=`uname -m`
    fi
    case $ARCH in
	    i?86) ARCH=i386;;
    esac

    if [ -z "${SUBARCH}" ]
    then
	SUBARCH=${ARCH}
    fi
    case $SUBARCH in
	    i?86) SUBARCH=i386;;
    esac


    if [ -n "${KERNEL_CONFIG_FILE}" ]
    then
	echo "Making local copy of kernel source, for ${KERNEL_CONFIG_FILE}."
	# if there is a KERNEL_CONFIG_FILE, then we have to
	# lndir, and "make oldconfig" the kernel to get something working.

	LOCAL_KERNEL_SRC=`pwd`/OUTPUT${KLIPS_MODULE}/$kernel_var_name

	rm -rf ${LOCAL_KERNEL_SRC}
	mkdir -p ${LOCAL_KERNEL_SRC}

        # get ourselves a kernel source tree, which is configured
        (cd ${LOCAL_KERNEL_SRC} && lndir -silent $KERNEL_SRC . )

	# this directory needs to really be a symlink.
	rm -r ${LOCAL_KERNEL_SRC}/include/asm

	cp ${KERNEL_CONFIG_FILE} ${LOCAL_KERNEL_SRC}/.config

	(cd ${LOCAL_KERNEL_SRC} && make ARCH=${ARCH} SUBARCH=${SUBARCH} oldconfig ) >OUTPUT${KLIPS_MODULE}/oldconfig.txt

	# repoint ourselves here, so we use the just configured sources.
	KERNEL_SRC=${LOCAL_KERNEL_SRC}
    fi


    # make this name absolute.
    MODULE_DEF_INCLUDE=`pwd`/$MODULE_DEF_INCLUDE

    if [ -z "${MODULE_DEFCONFIG}" ]
    then
	MODULE_DEFCONFIG=/dev/null
    else
	MODULE_DEFCONFIG=`pwd`/$MODULE_DEFCONFIG
    fi

    rm -f OUTPUT${KLIPS_MODULE}/module/ipsec.o

    cmd="(cd $FREESWANSRCDIR && make KERNELSRC=$KERNEL_SRC MODBUILDDIR=$moddir FREESWANSRCDIR=$FREESWANSRCDIR MODULE_DEFCONFIG=${MODULE_DEFCONFIG} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} ARCH=${ARCH} SUBARCH=${SUBARCH} module )"
    echo "# run as" >OUTPUT${KLIPS_MODULE}/doit.sh
    echo "$cmd" >>OUTPUT${KLIPS_MODULE}/doit.sh
    . OUTPUT${KLIPS_MODULE}/doit.sh

    if [ -r OUTPUT${KLIPS_MODULE}/module/ipsec.o ]
    then
	success=true
    fi

    if [ -n "${KERNEL_CONFIG_FILE}" ]
    then
       if [ -z "${KERNEL_PATCH_LEAVE_SOURCE}" ]
       then
	    rm -r ${KERNEL_CONFIG_FILE}
       fi
    fi

    case "$success" in
    true)	exit 0 ;;
    *)		exit 1 ;;
    esac
}

# test entry point:
module_compile() {
    testdir=$1
    testexpect=$2

    echo '****MODULE COMPILE RUNNING' $testdir '*******'

    export UML_BRAND="$$"
    ( preptest $testdir module_compile && do_module_compile_test )
    stat=$?
    if [ $stat = 99 ]
    then
        echo Test missing parts.
	stat='missing parts'
    fi

    recordresults $testdir "$testexpect" "$stat" $testdir
}


###################################
#
#  test type: umlXhost - a test with many hosts under control
#
###################################

do_umlX_test() {

    prerunsetup

    success=true
    failnum=1

    # these are network names
    EASTOUTPUT=''
    WESTOUTPUT=''
    PUBOUTPUT=''

    EXP2_ARGS=''

    if [ -n "$EAST_INPUT" ]
    then
	EXP2_ARGS="$EXP2_ARGS -e $EAST_INPUT"
    fi

    if [ -n "$WEST_INPUT" ]
    then
	EXP2_ARGS="$EXP2_ARGS -w $WEST_INPUT"
    fi

    if [ -n "$PUB_INPUT" ]
    then
	EXP2_ARGS="$EXP2_ARGS -p $PUB_INPUT"
    fi

    if [ -z "$XHOST_LIST" ]
    then
	XHOST_LIST="EAST WEST JAPAN"
    fi

    export XHOST_LIST

    # Xhost script takes things from the environment.
    for host in $XHOST_LIST
    do
       verboseecho "Processing exports for $host"
       verboseecho
       lhost=`echo $host | tr 'A-Z' 'a-z'`

       local startvar
       startvar=${host}_START
       if [ -z "${!startvar}" ]
       then
            local startdir
	    local starthost
	    starthost=${host}HOST
	    startdir=$POOLSPACE/${!starthost}
	    if [ -n "$KLIPS_MODULE" ]
	    then
		eval ${host}_START=$startdir/startmodule.sh
	    else
	        eval ${host}_START=$startdir/start.sh
            fi
       fi
       export ${host}_START

       eval "REF_${host}_CONSOLE_RAW=OUTPUT${KLIPS_MODULE}/${lhost}console.txt"
       export REF_${host}_CONSOLE_RAW
       export ${host}_INIT_SCRIPT
       export ${host}_RUN_SCRIPT
       export ${host}_RUN2_SCRIPT
       export ${host}_RUN3_SCRIPT
       export ${host}_RUN4_SCRIPT
       export ${host}_RUN5_SCRIPT
       export ${host}_FINAL_SCRIPT
    done

    if [ -n "$REF_EAST_OUTPUT" ]
    then
	EASTOUTPUT=`basename $REF_EAST_OUTPUT .txt `
	EXP2_ARGS="$EXP2_ARGS -E OUTPUT${KLIPS_MODULE}/$EASTOUTPUT.pcap"
    fi

    if [ -n "$REF_WEST_OUTPUT" ]
    then
	WESTOUTPUT=`basename $REF_WEST_OUTPUT .txt `
	EXP2_ARGS="$EXP2_ARGS -W OUTPUT${KLIPS_MODULE}/$WESTOUTPUT.pcap"
    fi

    if [ -n "$REF_PUB_OUTPUT" ]
    then
	PUBOUTPUT=`basename $REF_PUB_OUTPUT .txt`
	EXP2_ARGS="$EXP2_ARGS -P OUTPUT${KLIPS_MODULE}/$PUBOUTPUT.pcap"
    fi

    if [ "X$ARPREPLY" = "X--arpreply" ]
    then
	EXP2_ARGS="$EXP2_ARGS -a"
    fi

    if [ -n "$NETJIG_EXTRA" ]
    then
	EXP2_ARGS="$EXP2_ARGS -N $NETJIG_EXTRA"
    fi

    EXP2_ARGS="$EXP2_ARGS "`setup_additional_hosts`

    rm -f OUTPUT${KLIPS_MODULE}/eastconsole.txt
    rm -f OUTPUT${KLIPS_MODULE}/westconsole.txt
    rm -f OUTPUT${KLIPS_MODULE}/japanconsole.txt

    cmd="expect -f $UTILS/Xhost-test.tcl -- -n $NJ $EXP2_ARGS "
    $NETJIGDEBUG && echo $cmd
    eval $cmd

    pcap_filter west   "$REF_WEST_OUTPUT" "$WESTOUTPUT" "$REF_WEST_FILTER"
    pcap_filter east   "$REF_EAST_OUTPUT" "$EASTOUTPUT" "$REF_EAST_FILTER"
    pcap_filter public "$REF_PUB_OUTPUT"  "$PUBOUTPUT"  "$REF_PUB_FILTER"

    for host in $XHOST_LIST
    do
       local consoleref
       consoleref=REF_${host}_CONSOLE_OUTPUT
       lhost=`echo $host | tr 'A-Z' 'a-z'`

	if [ -n "${!consoleref}" ]
	then
	    consolediff $lhost OUTPUT${KLIPS_MODULE}/${lhost}console.txt ${!consoleref}
	fi
    done

    case "$success" in
    true)	exit 0 ;;
    *)		exit 1 ;;
    esac
}


# test entry point:
umlXhost() {
    testdir=$1
    testexpect=$2

    echo '***** UML 3HOST RUNNING' $testdir '*******'

    export UML_BRAND="$$"
    ( preptest $testdir umlXhost && do_umlX_test )
    stat=$?

    recordresults $testdir "$testexpect" "$stat" $testdir
}

#
# $Id: functions.sh,v 1.101 2003/11/25 00:22:53 mcr Exp $
#
# $Log: functions.sh,v $
# Revision 1.101  2003/11/25 00:22:53  mcr
# 	have skiptest make up a fake TEST_PURPOSE, so there are
# 	no complaints from regressrecord.
#
# Revision 1.100  2003/11/05 07:38:30  dhr
#
# make functions.sh more robust
#
# Revision 1.99  2003/11/05 04:35:56  dhr
#
# clarify shell variable export command
#
# Revision 1.98  2003/10/31 02:43:33  mcr
# 	pull up of port-selector tests
#
# Revision 1.97  2003/10/29 20:52:37  dhr
#
# functions.sh: silence grep; add "rogue" to status if rogue was found
#
# Revision 1.96  2003/10/28 03:03:33  dhr
#
# Refine testing scripts:
# - put timeout and eof handlers in each expect script
# - kill more rogue processes: even those with unreadable(!) /proc entries
# - improve reporting of skipped tests
# - make "recordresults" do more, simplifying every caller
# - speed up UML shutdown by using "halt -p -r" (requires many reference log updates)
#
# Revision 1.95  2003/10/21 15:08:03  dhr
#
# - show more raw detail within braces of testing report
# - make functions.sh clearer
# - silence the "kill" commands in function.sh that probe for successful killing
#
# Revision 1.94  2003/10/16 03:14:56  dhr
#
# Many minor improvements to functions.sh:
# - add quotes for good shell hygiene
# - try harder to kill rogue UML processes
# - use "case" to analyze $success (``if $success'' fails whe $success is "missing")
# The use of $success is still disorganized and confusing.  With some work
# it could be used to produce better diagnostics.
#
# Revision 1.93  2003/10/16 02:56:47  dhr
#
# clean up whitespace
#
# Revision 1.92  2003/10/15 15:31:57  dhr
#
# functions.sh: let recordresults survive a testparams.sh that exits
#
# Revision 1.91  2003/10/14 22:07:09  dhr
#
# functions.sh: let recordresults survive a missing testparams.sh
#
# Revision 1.90  2003/10/14 14:23:29  dhr
#
# Fix some problems with "make check" (testing/utils/functions.sh):
# - Make sure that each "source" or "." command uses a pathname with a slash.
#   Otherwise the $PATH will be used.
# - Fix the TEST_PURPOSE analysis: source testparams.sh in recordresults.
#   Note when TEST_PURPOSE isn't understood.
# - remove redundant "rm -rf" commands
#
# Revision 1.89  2003/10/01 16:13:56  dhr
#
# Make the -modules hack in testing/klips/dotests.sh actually work:
# add ${KLIPS_MODULE} to almost every path with OUTPUT that didn't already have it.
#
# Revision 1.88.2.1  2003/10/29 02:09:56  mcr
# 	set test purpose to REGRESS for library tests.
#
# Revision 1.88  2003/08/21 22:38:06  mcr
# 	sense of test was wrong for MODULE_DEFCONFIG
#
# Revision 1.87  2003/08/21 22:35:11  mcr
# 	if we didn't specify a MODULE_DEFCONFIG, then use /dev/null
#
# Revision 1.86  2003/08/18 16:32:48  mcr
# 	export 3,4,5 RUN script variables.
#
# Revision 1.85  2003/05/21 14:10:31  mcr
# 	look for core files produced by pluto, and save them to the
# 	OUTPUT directory, changing failure state to "core".
#
# Revision 1.84  2003/05/03 23:26:02  mcr
# 	added RCS Ids.
#
#
