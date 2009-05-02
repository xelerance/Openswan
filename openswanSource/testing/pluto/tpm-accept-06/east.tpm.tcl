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

# drop all informational messages (as they contain delete's)
proc processRawPacket {state conn md} {
    return "nothing"
}

# just discard them all!
proc avoidEmittingNotify {state pbs hdr} {
    puts stderr "not sending any delete notification"
    return "stf_ignore"
}

# just discard them all!
proc avoidEmittingDelete {state pbs hdr} {
    puts stderr "not sending any delete notification"
    return "stf_ignore"
}
