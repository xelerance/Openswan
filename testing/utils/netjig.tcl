global theprompt
set theprompt {([a-zA-Z0-9]*):.*# }

proc netjigdebug {msg} {
    global env
    if {[info exists env(NETJIGVERBOSE)]} {
        puts stderr $msg
    }
}

proc netjigcmddebug {msg} {
    global env
    if {[info exists env(NETJIGTESTDEBUG)]} {
	if {$env(NETJIGTESTDEBUG) == "netjig"} {
	    puts -nonewline stderr $msg
	}
    }
}

proc sendnjcmd {netjig cmd} {
    global expect_out(buffer)

    # expect -i $netjig "OK netjig>"
    expect {
    	-i $netjig
	eof	{ puts stderr "EOF in sendnjcmd" }
	timeout	{ puts stderr "timeout in sendnjcmd" }
	"OK netjig>"
    }
    set ncmd [join $cmd]
    netjigcmddebug "Sending $ncmd\n"
    send -i $netjig "$ncmd\n"
    
#    exp_internal 1
    expect {
	-i $netjig
	-re {OK ([0-9]*) LINES} {
	    netjigcmddebug "There are $expect_out(1,string) lines of output\n"
	    return $expect_out(1,string)
	}
	-re {FAIL ([0-9]*) LINES} {
	    set lines $expect_out(1,string)
	    puts "Command failed with output $lines!"
	    exp_internal 1
	    expect -i $netjig -re "netjig>"
	    exit
	}
	timeout {
	    puts "Timeout while talking to netjig for $cmd"
	    puts stderr "Timeout while talking to netjig for $cmd"
	    exit
	}	    
	eof {
	    puts "EOF while talking to netjig for $cmd"
	    puts stderr "EOF while talking to netjig for $cmd"
	    exit
	}	    
    }

    netjigcmddebug "There are $expect_out(1,string) lines of output\n"
    return $expect_out(1,string)
}

proc newswitch {netjig args} {
    global env
    global expect_out(buffer)
    set lines [sendnjcmd $netjig "NEWSWITCH $args"]

#    exp_internal 1
    while {$lines > 0} {
	expect {
		-i $netjig
		eof	{ puts stderr "EOF in newswitch" }
		timeout	{ puts stderr "timeout in newswitch" }
		-re {([^\r\n]*)=([^\r\n]*)}
	}
	set var   $expect_out(1,string)
	set value $expect_out(2,string)
	netjigcmddebug "Setting $var to $value|\n"
	set env($var) $value
	set lines [expr $lines - 1]
    }
}

proc njcmd {netjig cmdline} {
    global env
    global expect_out(buffer)
    set lines [sendnjcmd $netjig "$cmdline"]

    while {$lines > 0} {
	expect {
		-i $netjig
		timeout	{ puts stderr "timeout in njcmd" }
		eof	{ puts stderr "EOF in njcmd" }
		-re {([^\r\n]*)\n}
	}
	set lines [expr $lines - 1]
    }
}    

proc playnjscript {netjig scriptname} {
    set initscript [open $scriptname r]

    while {[gets $initscript line] >= 0} {
	# skip empty lines.
	if {[string length [string trimright $line]] == 0} {
	    continue;
	}	
	njcmd $netjig $line
    }
}

proc netjigsetup {netjig} {
    global env

    # set the packet replay rate, if necessary.
    if {[info exists env(PACKETRATE)]} {
	netjigdebug "setting PACKETRATE: $env(PACKETRATE)"
	njcmd $netjig "setrate $env(PACKETRATE)"
    }
}

proc expectprompt {umlid msg} {
    global theprompt

    trace variable expect_out(buffer) w log_by_tracing
    expect {
	-i $umlid
	-re $theprompt {}
	-re {^\<.\>.*\n}   { exp_continue }
	-re {([^\r\n]*)\n} { exp_continue }
	eof {
	    puts "Cannot find prompt $msg (eof)"
	    puts stderr "Can not find prompt $msg (eof)"
	    shutdownumls
	    exit;
	}
	timeout { 
	    puts "Cannot find prompt $msg (timeout)"
	    puts stderr "Can not find prompt $msg (timeout)"
	    # this ought to be pointless:
	    send -i $umlid "\n echo prompt missing \n"
	    exit
	}
    }
}

proc playscript {umlid scriptname} {
    global theprompt

    trace variable expect_out(buffer) w log_by_tracing

#    exp_internal 1
    set initscript [open $scriptname r]
    while {[gets $initscript line] >= 0} {
	# skip empty lines.
	if {[string length [string trimright $line]] == 0} {
	    continue;
	}	
	if {[string match [string index [string trimleft $line] 0] \#] == 0} {
	    expectprompt $umlid "in playscript $scriptname"

	    # eat any additional previous output
	    expect -i $umlid -gl "*"

	    send -i $umlid -- "$line\r"
	}
    }
    close $initscript
}

proc record {netjig network recordfile} {
    sendnjcmd $netjig "RECORDFILE --switchname=$network --recordfile=$recordfile\n"
}

proc setupplay {netjig network playfile} {
    sendnjcmd $netjig "PLAYFILE --switchname=$network --playfile=$playfile\n"
}

proc waitplay {netjig} {
    set timeout 900
    sendnjcmd $netjig "WAITPLAY\n"
}

proc log_by_tracing {array element op} {
    uplevel {
	global consoleout
	set id $expect_out(spawn_id)

#	puts stderr "\n***** Tracing out ID: $id *******\n"
	if {[ info exists consoleout($id) ]} {
	    puts -nonewline $consoleout($id) $expect_out(buffer)
	}
    }
}

proc shutdown {umlname} {
    system "uml_mconsole $umlname halt"
}

proc shutdownumls {} {
    global umlid
    global managed_hosts

    foreach host $managed_hosts {
	shutdown $host
    }

    foreach host $umlid(extra_hosts) {
	shutdown $host
    }
}


proc startuml {umlname} {
    global umlid
    global consoleout

    if {[info exists umlid($umlname,consolefile)]} {
	set console [open $umlid($umlname,consolefile) w]
	puts $console "Starting UML $umlid($umlname,program)"
    } else {
	set console [open "OUTPUT/$umlname-console-default.txt" w]
    }

    netjigdebug "Starting UML $umlid($umlname,program) for $umlname"

    set umlid($umlname,pid) [spawn $umlid($umlname,program) single]
    set umlid($umlname,spawnid) $spawn_id

    if {[info exists umlid($umlname,consolefile)]} {
	puts $console "spawn $umlid($umlname,program) single"
	netjigdebug "Capturing console output to $umlid($umlname,consolefile)"
    } 
    set consoleout($umlid($umlname,spawnid)) $console
}

proc loginuml {umlname} {
    global umlid
    global theprompt
    
    trace variable expect_out(buffer) w log_by_tracing
    expect {
    	-i $umlid($umlname,spawnid)
	timeout	{ puts stderr "timeout in logginuml" }
	eof	{ 
	          puts stderr "EOF in loginuml" 
    	          shutdownumls
	}
	-exact "normal startup):"
    }
    netjigdebug "\nLogging in to $umlname"
    send -i $umlid($umlname,spawnid) -- "root\r"
}

proc inituml {umlname} {
    global umlid
    global env
    global theprompt
    
    expectprompt $umlid($umlname,spawnid) "before loading module ($umlname)"

    send -i $umlid($umlname,spawnid) -- "echo Starting loading module\r"

    expectprompt $umlid($umlname,spawnid) "for bash exec ($umlname)"

    send -i $umlid($umlname,spawnid) -- "exec bash --noediting\r"

    if {[info exists env(KLIPS_MODULE)]} {
	puts stderr "Loading module into $umlname"

	trace variable expect_out(buffer) w log_by_tracing
	set expect_out(spawn_id) $umlid($umlname,spawnid)
	set expect_out(buffer) ""

	expectprompt $umlid($umlname,spawnid) "before recording memory level ($umlname)"

	send -i $umlid($umlname,spawnid) -- "cat /proc/meminfo >/tmp/proc_meminfo-no-ipsec-mod-01\r" 
	expectprompt $umlid($umlname,spawnid) "for insmod ($umlname)"

	send -i $umlid($umlname,spawnid) -- "insmod /ipsec.o\r"
    } 

    expectprompt $umlid($umlname,spawnid) "for post-insmod ($umlname)"

    send -i $umlid($umlname,spawnid) -- "echo Finished loading module\r"

    expectprompt $umlid($umlname,spawnid) "for klogd ($umlname)"

    send -i $umlid($umlname,spawnid) -- "klogd -c 4 -x -f /tmp/klog.log\r"

    if {[info exists umlid($umlname,initscript)]} {
	playscript $umlid($umlname,spawnid) $umlid($umlname,initscript)
	netjigdebug "$umlname Initialization done"
    }
}

proc runXuml {umlname pass} {
    global umlid
    global env
    global theprompt

    # upcase host name
    set uphost [string toupper $umlname]

    set scriptname run${pass}script
    
    set varname $uphost
    append varname _RUN${pass}_SCRIPT
    set_from_env $umlname $scriptname $varname

    if {[info exists umlid($umlname,$scriptname)]} {
	if {[file exists $umlid($umlname,$scriptname)]} {
	    playscript $umlid($umlname,spawnid) $umlid($umlname,$scriptname)
	    netjigdebug "$umlname run script($pass) $umlid($umlname,$scriptname) done"
	    return 1
	} else {
	    puts stderr "runXuml($umlname,$pass): $umlid($umlname,$scriptname) does not exist."
	    return 0
	}
    } else {
	netjigdebug "$umlname no run script for pass $pass"
	return 0
    }
}

proc runuml {umlname} {
    global umlid
    global env
    global theprompt

    runXuml $umlname ""
}

proc run2uml {umlname} {
    global umlid
    global env
    global theprompt

    runXuml $umlname 2
}

proc initdns {umlname} {
    global umlid
    global env
    global theprompt

    expectprompt $umlid($umlname,spawnid) "for bash exec ($umlname)"

    send -i $umlid($umlname,spawnid) -- "exec bash --noediting\r"

    expectprompt $umlid($umlname,spawnid) "before sucking in profile ($umlname)"

    send -i $umlid($umlname,spawnid) -- "source \$HOME/.profile\r"

    expectprompt $umlid($umlname,spawnid) "before starting bind ($umlname)"

    send -i $umlid($umlname,spawnid) -- "named\r"

    expectprompt $umlid($umlname,spawnid) "after starting bind ($umlname)"

    send -i $umlid($umlname,spawnid) -- "inetd\r"

    expectprompt $umlid($umlname,spawnid) "after starting inetd ($umlname)"
}

proc killdns {umlname} {
    global umlid
    
    trace variable expect_out(buffer) w log_by_tracing

    #exp_internal 1
    netjigdebug "Sending halt to $umlname!"

    send   -i $umlid($umlname,spawnid)     "halt -p -f\r"

    netjigdebug "Waiting for final message"
    expect {
	-i $umlid($umlname,spawnid)
	timeout	{ puts stderr "timeout in killdns" }
	eof	{ puts stderr "EOF in killdns" }
	-exact "Power down." 
    }
    expect -i $umlid($umlname,spawnid) -gl "*"
}


proc killuml {umlname} {
    global umlid

    trace variable expect_out(buffer) w log_by_tracing

    if {[info exists umlid($umlname,finalscript)]} {
	playscript $umlid($umlname,spawnid) $umlid($umlname,finalscript)
	netjigdebug "Finalscript done"
    } 

    netjigdebug "Sending halt to $umlname!"
    # absorb anything there.

    expectprompt $umlid($umlname,spawnid) "for ipsec setup stop ($umlname)"
    send   -i $umlid($umlname,spawnid)     "ipsec setup stop\r"

    expectprompt $umlid($umlname,spawnid) "for klogd dump ($umlname)"
    send -i $umlid($umlname,spawnid) "kill `cat /var/run/klogd.pid`; cat /tmp/klog.log\r"

    expectprompt $umlid($umlname,spawnid) "for halt ($umlname)"
    send   -i $umlid($umlname,spawnid)     "halt -p -f\r"

    netjigdebug "Waiting for final message"
    expect {
	-i $umlid($umlname,spawnid)
	timeout	{ puts stderr "timeout in killuml" }
	eof	{ puts stderr "EOF in killuml" }
	-exact "Power down." 
    }
    expect -i $umlid($umlname,spawnid) -gl "*"
}

proc process_extra_host {optarg} {
   global umlid

   # format of arg is host=program[, ]host=program.
   set hostlist [split $optarg ", "]
   foreach hosttype $hostlist {
       set h       [split $hosttype =]
       set host    [lindex $h 0]
       set program [lindex $h 1]
       set umlid($host,program) $program
       lappend umlid(extra_hosts) $host
   }
}

proc set_from_env {host param varname} {
    global umlid
    global env
    
    #puts -nonewline stderr "Looking for $varname..."
    if {[info exists env($varname)]} {
	#puts -nonewline stderr "found it: $env($varname)"
	set umlid($host,$param) $env($varname)
    }
    #netjigdebug ""
}


# For each host, the following variables are examined:
# ${HOST}_INIT_SCRIPT     the script to initialize the host with
# ${HOST}_RUN_SCRIPT      the script to run the host with
# ${HOST}_FINAL_SCRIPT    the script to run the host with
# ${HOST}_START   the program to invoke the UML
# REF_${HOST}_CONSOLE_OUTPUT      where to redirect the console output to

proc process_host {host} {
    global umlid
    global env

    # upcase me
    set uphost [string toupper $host]

    set varname $uphost
    append varname _INIT_SCRIPT
    set_from_env $host initscript $varname
	
    set varname $uphost
    append varname _RUN_SCRIPT
    set_from_env $host runscript $varname

    set varname $uphost
    append varname _RUN2_SCRIPT
    set_from_env $host run2script $varname

    set varname $uphost
    append varname _FINAL_SCRIPT
    set_from_env $host finalscript $varname
    
    set varname $uphost
    append varname _START
    set_from_env $host program $varname
    
    set varname REF_
    append varname $uphost
    append varname _CONSOLE_RAW
    set_from_env $host consolefile $varname
}
    


match_max -d 10000
