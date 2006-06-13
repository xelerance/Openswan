#!/usr/bin/expect --

#
# $Id: localswitches.tcl,v 1.5 2004/04/03 19:44:52 ken Exp $
#

source $env(OPENSWANSRCDIR)/testing/utils/GetOpts.tcl
source $env(OPENSWANSRCDIR)/testing/utils/netjig.tcl

set netjig_prog $env(OPENSWANSRCDIR)/testing/utils/uml_netjig/uml_netjig

set arpreply ""
set umlid(extra_hosts) ""

set env(NETJIGVERBOSE) 1

set netjig1 [netjigstart]

netjigsetup $netjig1

foreach net $managednets {
    process_net $net
}

foreach net $managednets {
    calc_net $net
}

foreach net $managednets {
    newswitch $netjig1 "$net"
}

foreach host $argv {
    system "$host single &"
}

foreach net $managednets {
    if {[info exists umlid(net$net,play)] } {
	puts "Will play pcap file $umlid(net$net,play) to network '$net'\r\n"
	setupplay $netjig1 $net $umlid(net$net,play) "--rate=ontick"
    }
}


puts "\r\nExit the netjig when you are done\r\n"

set timeout -1
interact -reset -i $netjig1 

foreach host $argv {
    system "uml_mconsole $host halt"
}






