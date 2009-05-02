proc is_ipsec_sa_established {state} {
    global STATE_MAIN_R2 STATE_AGGR_R0 STATE_AGGR_I1

    set st_state [state_st_state_get $state]

    if { ($STATE_MAIN_R2 <= $st_state) && ($STATE_AGGR_R0 != $st_state) && ($STATE_AGGR_I1 != $st_state)} {
	return 1
    } {
	return 0
    }
}

proc processRawPacket {state conn md} {
    set iface_port [msg_digest_iface_get  $md]
    set iface_dev  [iface_port_ip_dev_get  $iface_port]
    set if_name    [iface_dev_id_rname_get $iface_dev]
    set ipl        [addrtot [iface_port_ip_addr_get $iface_port] 0 1024]
    set ip         [lindex $ipl 1]
    puts stderr "md: $md"
    puts stderr "packet from: $ip"
}

proc recvMessage {state conn md} {
    puts stderr "recvMessage $state $conn $md"
}

proc changeState {state conn md} {
    puts stderr "changeState $state $conn $md"
}

proc is_null_pointer {pointer} {
    if {[string length $pointer] == 0 || $pointer == "NULL"} {
	return 1
    }
    return 0
}

proc adjustFailure {state conn md} {
    if {[is_null_pointer $state]} {
	return
    } {
	set st_state [state_st_state_get $state]
    }

    puts stderr "adjustFailure $state $conn $md: state $st_state"

    if { [is_ipsec_sa_established $state]} {
	set shared_secret_chunk [state_st_sec_chunk_get $state]
	set shared_secret_bytes [chunk_ptr_get $shared_secret_chunk]
	set shared_secret_len   [chunk_len_get $shared_secret_chunk]
	set shared_secret [cdata $shared_secret_bytes $shared_secret_len]
	openswan_DBG_dump "shared-secret" $shared_secret
    } else {
	puts stderr "AF: not yet encrypted"
    }
}

proc avoidEmitting {state conn md} {
    puts stderr "avoidEmitting $state $conn $md"
}

