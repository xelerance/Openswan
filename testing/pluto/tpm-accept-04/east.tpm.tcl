set test_stage "none"
set stage4b_count 0
set stage4c_count 0

proc is_null_pointer {pointer} {
    if {[string length $pointer] == 0 || $pointer == "NULL"} {
	return 1
    }
    return 0
}

proc is_ipsec_sa_established {state} {
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

proc processRawPacket {state conn md} {
    set iface_port [msg_digest_iface_get  $md]
    set iface_dev  [iface_port_ip_dev_get  $iface_port]
    set if_name    [iface_dev_id_rname_get $iface_dev]
    set ipl        [addrtot [iface_port_ip_addr_get $iface_port] 0 1024]
    set ip         [lindex $ipl 1]

    puts stderr "tcl says packet from: $ip"
    return "ignore"
}

proc recvMessage {state conn md} {
    global STATE_MAIN_R1
    global STATE_QUICK_R0
    global test_stage

    return "ignore"
}

proc log_key_iv {msg state} {
    global keys
    set key_chunk [state_st_enc_key_get $state]
    set iv_bytes  [state_st_new_iv_get $state]
    set iv_len    [state_st_new_iv_len_get $state]
    set ike_key   [cdata [chunk_ptr_get $key_chunk] [chunk_len_get $key_chunk]]
    set iv        [cdata $iv_bytes $iv_len]

    # store keys for later.
    set keys($msg,key) $ike_key
    set keys($msg,iv)  $iv
    openswan_DBG_dump "$msg IKE-key" $ike_key
    openswan_DBG_dump "$msg  new-IV" $iv
}

proc preDecrypt {state pb off len} {
    global test_stage

    if {[is_null_pointer $state]} {
	return
    }

    set st_state  [state_st_state_get $state]

    if {[string compare $test_stage "t04a"] == 0} {
	puts stderr [format "t04a in  st:%02d" $st_state] 
	log_key_iv [format "t04a st:%d" $st_state] $state
    }
    
    return "ignore"
}

proc preEncrypt {state pb off len} {
    global test_stage

    if {[is_null_pointer $state]} {
	return
    }

    set st_state  [state_st_state_get $state]

    if {[string compare $test_stage "t04a"] == 0} {
	puts stderr [format "t04a out st:%02d" $st_state]
	log_key_iv [format "t04a st:%d" $st_state] $state
    }
    
    return "ignore"
}
   

proc postEncrypt {state pb off len} {
    global STATE_MAIN_R2 STATE_QUICK_R1
    global test_stage
    global stage4b_count stage4c_count

    if {[is_null_pointer $state]} {
	return
    }
    set st_state  [state_st_state_get $state]
    set len [int_value $plen]

    if {[string compare $test_stage "t04b"] == 0
        && $stage4b_count < 2} {
	
	incr stage4b_count
	puts stderr [format "t04b inm st:%02d" $st_state] 
	set logmsg [format "t04b st:%d" $st_state] 

	set ikemsg [pbs_bytes $pb 256]
	openswan_DBG_dump $logmsg $ikemsg

	if {$st_state == $STATE_MAIN_R2} {
	    # corrupt outgoing IKE message.
	    
	    puts stderr "Corrrupting with ABCD"
	    pbs_poke $pb 20 65
	    pbs_poke $pb 21 66
	    pbs_poke $pb 22 67
	    pbs_poke $pb 23 68
	}
	set logmsg [format "t04b st:%d" $st_state] 
	set ikemsg [pbs_bytes $pb 256]
	openswan_DBG_dump $logmsg $ikemsg
    }

    if {[string compare $test_stage "t04c"] == 0
        && $stage4c_count < 2} {
	
	incr stage4c_count
	set ikemsg [pbs_bytes $pb 256]
	puts stderr [format "t04c inm st:%02d" $st_state] 
	set logmsg [format "t04c st:%d" $st_state] 
	openswan_DBG_dump $logmsg $ikemsg

	if {$st_state == $STATE_QUICK_R1} {
	    # corrupt outgoing IKE phase 2 message.
	    
	    puts stderr "Corrrupting with XYZX"
	    pbs_poke $pb 20 88
	    pbs_poke $pb 21 89
	    pbs_poke $pb 22 90
	    pbs_poke $pb 23 88
	}
	set logmsg [format "t04c st:%d" $st_state] 
	set ikemsg [pbs_bytes $pb 256]
	openswan_DBG_dump $logmsg $ikemsg
    }

    return "ignore"
}

proc postDecrypt {state pb off len} {
    global test_stage

    set st_state  [state_st_state_get $state]

    if {[string compare $test_stage "t04a"] == 0} {
	set ikemsg [cdata $buf $len]

	puts stderr [format "t04a inm st:%02d" $st_state] 
	set logmsg [format "t04a st:%d" $st_state] 
	openswan_DBG_dump $logmsg $ikemsg
    }

    return "ignore"
}
   

