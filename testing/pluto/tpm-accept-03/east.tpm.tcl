set test_stage "none"

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
}

proc recvMessage {state conn md} {
    puts stderr "recvMessage $state $conn $md"

    global STATE_MAIN_R1
    global STATE_QUICK_R0
    global test_stage

    if {[is_null_pointer $state]} {
	return
    } {
	set st_state [state_st_state_get $state]
	set from_state [msg_digest_from_state_get $md]
    }

    puts stderr "stage: $test_stage state: $from_state MR1: $STATE_MAIN_R1 MQ0: $STATE_QUICK_R0"
    if {[string compare $test_stage "t03a"] == 0} {
	if {$from_state == $STATE_MAIN_R1} {
	    puts stderr "Pausing for 60 seconds in phase 1"
	    after 60000
	}
    }

    if {[string compare $test_stage "t03c"] == 0} {
	if {$from_state == $STATE_QUICK_R0} {
	    puts stderr "Pausing for 60 seconds in phase 2"
	    after 60000
	}
    }
}

proc preDecrypt {state pb off len} {
  	return "ignore" 
}

proc preEncrypt {state pb off len} {
  	return "ignore" 
}

proc postDecrypt {state pb off len} {
  	return "ignore" 
}

proc postEncrypt {state pb off len} {
  	return "ignore" 
}

proc changeState {state conn md} {
  	return "ignore" 
}

proc adjustFailure {state conn md} {
  	return "ignore" 

}

proc avoidEmitting {state conn md} {
  	return "ignore" 
}

