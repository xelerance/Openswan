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
    global ISAKMP_XCHG_INFO;

    set hdr  [msg_digest_hdr_get $md]
    set xchg [isakmp_hdr_isa_xchg_get $hdr]

    if {$xchg == $ISAKMP_XCHG_INFO} {
	puts stderr "Got exchange type: $xchg -- ignoring"
	return "stf_ignore"
    }
    return "nothing"
}

proc recvMessage {state conn md} {
    return "ignore"
}

proc preDecrypt {state pbs off len} {
    return "ignore"
}

proc preEncrypt {state pbs off len} {
    return "ignore"
}
   

proc postEncrypt {state pbs off len} {
    return "ignore"
}

proc postDecrypt {state pbs off len} {
    return "ignore"
}

proc changeState {state conn md} {
    return "ignore"
}

proc adjustFailure {state conn md} {
    return "ignore"
}

proc avoidEmitting {state conn md} {
    return "nothing"
}

proc adjustTimers {state conn md} {
    global STATE_QUICK_R2 STATE_QUICK_I2 STATE_MAIN_R2

    if {[is_null_pointer $state]} {
	puts stderr "FOO"
	return "ignore"
    } 

    set st_state [state_st_state_get $state]

    if { $st_state != $STATE_MAIN_R2 } {
	set newtime 900
	set oakley [state_st_oakley_get $state]
	set negtime [oakley_trans_attrs_life_seconds_get $oakley]
	oakley_trans_attrs_life_seconds_set $oakley $newtime
	
	puts stderr "Adjusting IKE timeout to large number. $negtime -> $newtime"
    }

    if { ($STATE_QUICK_R2 != $st_state) && ($STATE_QUICK_I2 != $st_state)} {
	set newtime 900
	set espinfo [state_st_esp_get $state]
	set attrs [ipsec_proto_info_attrs_get $espinfo]
	set negtime [ipsec_trans_attrs_life_seconds_get $attrs]
	ipsec_trans_attrs_life_seconds_set $attrs $newtime
	
	puts stderr "Adjusting IPsec timeout to large number. $negtime -> $newtime"
    }

    
    return "ignore"
}

# nothing.
proc avoidEmittingNotify {state pbs hdr} {
    return "ignore"
}
