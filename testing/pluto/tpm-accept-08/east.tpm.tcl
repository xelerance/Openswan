set test08_count 0

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

#
# this inserts the VID at the beginning of the packet.
#
proc insertVendorId {msg vendorid} {
    set len [pbs_offset_get $msg]
    set vidlen [expr ([string bytelength $vendorid] + 7) & 0xfffc]
    set newpb [pbs_create [expr $len + $vidlen]]

    puts stderr "Inserting VID($vidlen): $vendorid"

    # copy IKE header
    pbs_append $newpb 0 $msg 0 28
    set inLoc  28
    set outLoc 28

    set thispay [pbs_peek $msg 16]
    set thispayloc 16

    # copy the first payload if HASH or SA, since VID can not be first, cf:
    #   rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode

    global ISAKMP_NEXT_SA ISAKMP_NEXT_HASH
    for {} {$thispay == $ISAKMP_NEXT_SA || $thispay == $ISAKMP_NEXT_HASH} {} {
	set nextpay [pbs_peek $msg $inLoc]
	set nextpayloc $inLoc
	set paylen  [expr ([pbs_peek $msg [expr $inLoc + 2]] * 256) + [pbs_peek $msg [expr $inLoc + 3]]]

	puts stderr "copying payload($thispay) at $inLoc, np: $nextpay with len: $paylen"

	# copy payload to new message
	pbs_append $newpb $outLoc $msg $inLoc $paylen
	set outLoc [expr $outLoc + $paylen]
	
	# poke payload type in pointer to this payload.
	# most of the time, a no-op.
	#puts stderr "overwrriting previous np: newpb($thispayloc)=$thispay"
	pbs_poke $newpb $thispayloc $thispay
	set thispayloc $nextpayloc

	# cut payload from $msg
	set inLoc [expr $inLoc + $paylen]

	set thispay    $nextpay
    }

    #hexdump_pb "2: " $newpb

    # insert vendor ID as np.
    global ISAKMP_NEXT_VID			   
    pbs_poke $newpb $thispayloc $ISAKMP_NEXT_VID  

    set preVidLoc $outLoc
    # insert our VID ID payload
    pbs_poke $newpb $outLoc $thispay
    incr outLoc
    pbs_poke $newpb $outLoc 0
    incr outLoc
    set b1 [expr $vidlen >> 8] 
    set b2 [expr $vidlen & 0xff]
    puts stderr "VIDlen: $vidlen $b1 $b2" 
    pbs_poke $newpb $outLoc $b1
    incr outLoc 
    pbs_poke $newpb $outLoc $b2
    incr outLoc 
    
    binary scan $vendorid c* vidbytes
    
    foreach byte $vidbytes {
	pbs_poke $newpb $outLoc $byte
	incr outLoc
    }
    # round up.
    set outLoc [expr $vidlen + $preVidLoc]

    #hexdump_pb "3: " $newpb

    pbs_append $newpb $outLoc $msg $inLoc [expr $len - $inLoc]
    return $newpb
}

# this should be a sophisticated no-op.
proc preHash {state pb off len} {
  
    hexdump_pb "pb" $pb

    global ISAKMP_NEXT_SA
    global test08_count 
    
#    if {$test07_count < 5} {
	set newpb [insertVendorId $pb "CABLELABS"]
#   } else {
#	set newpb $pb
#    }
#    incr test08_count

    hexdump_pb "newpb" $newpb

    # copy newpb back over pb.
    set pb_size [pbs_offset_get $newpb]

    pbs_append $pb 0 $newpb 0 $pb_size

    #hexdump_pb "npb" $pb

    return "nothing"
}
   
