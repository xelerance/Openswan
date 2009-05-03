set test07_count 0

proc is_null_pointer {pointer} {
    if {[string length $pointer] == 0 || $pointer == "NULL"} {
	return 1
    }
    return 0
}

proc is_isakmp_sa_established {state} {
    global STATE_MAIN_R2 STATE_AGGR_R0 STATE_AGGR_I1

    if {[string length $state] == 0} {
	return 0
    }

    set st_state [state_st_state_get $state]

    if { ($STATE_MAIN_R2 <= $st_state) && ($STATE_AGGR_R0 != $st_state) && ($STATE_AGGR_I1 != $st_state)} {
	return 1
    } {
	return 0
    }
}

proc is_ipsec_sa_established {state} {
    global STATE_QUICK_R2 STATE_QUICK_I2

    if {[string length $state] == 0} {
	return 0
    }

    set st_state [state_st_state_get $state]

    if { ($STATE_QUICK_R2 == $st_state) || ($STATE_QUICK_I2 == $st_state)} {
	return 1
    } {
	return 0
    }
}

proc hexdump_pb {prefix pb} {

    set pb_size [pbs_offset_get $pb]
    puts stderr "$prefix size: $pb_size"

    for {set i 0} {$i < $pb_size} {set i [expr $i + 8]} {
	set line [format "%04d: %02x %02x %02x %02x  %02x %02x %02x %02x" \
		      $i \
		      [pbs_peek $pb [expr $i + 0]]		\
		      [pbs_peek $pb [expr $i + 1]]		\
		      [pbs_peek $pb [expr $i + 2]]		\
		      [pbs_peek $pb [expr $i + 3]]	        \
		      [pbs_peek $pb [expr $i + 4]]		\
		      [pbs_peek $pb [expr $i + 5]]		\
		      [pbs_peek $pb [expr $i + 6]]		\
		      [pbs_peek $pb [expr $i + 7]]]

	puts stderr "$prefix $line"
    }
}

proc copyMessageWithoutPayload {msg paynum} {
    set thispay [pbs_peek $msg 16]
    set thispayloc 16
    set len [pbs_offset_get $msg]
    set newpb [pbs_create $len]

    # copy IKE header
    pbs_append $newpb 0 $msg 0 28
    set len [expr $len - 28]
    set inLoc  28
    set outLoc 28

    puts stderr "starting with np=$thispay len: $len"
    for {} {$inLoc < $len && $thispay != 0} {} {
	set nextpay [pbs_peek $msg $inLoc]
	set nextpayloc $inLoc
	set paylen  [expr ([pbs_peek $msg [expr $inLoc + 2]] * 256) + [pbs_peek $msg [expr $inLoc + 3]]]

	#hexdump_pb "msg:" $msg
	#hexdump_pb "new:" $newpb

	if {$paynum != 0 && $thispay != $paynum} {
	    #puts stderr "copying payload($thispay) at $inLoc, np: $nextpay with len: $paylen"
	    # copy payload to new message
	    pbs_append $newpb $outLoc $msg $inLoc $paylen
	    set outLoc [expr $outLoc + $paylen]

	    # poke payload type in pointer to this payload.
	    # most of the time, a no-op.
	    #puts stderr "overwrriting previous np: newpb($thispayloc)=$thispay"
	    pbs_poke $newpb $thispayloc $thispay
	    set thispayloc $nextpayloc
	} else {
	    puts stderr "omitting paynum: $paynum"
	}

	#hexdump_pb "new2:" $newpb

	# cut payload from $msg
	set inLoc [expr $inLoc + $paylen]

	set thispay    $nextpay
    }

    return $newpb
}

# this should be a sophisticated no-op.
proc preEncrypt {state pb off len} {
  
    #hexdump_pb "pb" $pb

    global ISAKMP_NEXT_SA
    global test07_count 
    
    if {$test07_count < 5} {
	set newpb [copyMessageWithoutPayload $pb $ISAKMP_NEXT_SA]
    } else {
	set newpb [copyMessageWithoutPayload $pb 0]
    }
    incr test07_count

    #hexdump_pb "newpb" $newpb

    # copy newpb back over pb.
    set pb_size [pbs_offset_get $newpb]

    pbs_append $pb 0 $newpb 0 $pb_size

    #hexdump_pb "npb" $pb

    return "nothing"
}
   
