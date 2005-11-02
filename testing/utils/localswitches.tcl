#!/usr/bin/expect --

#
# $Id: localswitches.tcl,v 1.3 2003/08/18 16:31:34 mcr Exp $
#

source $env(FREESWANSRCDIR)/testing/utils/GetOpts.tcl
source $env(FREESWANSRCDIR)/testing/utils/netjig.tcl

set netjig_debug_opt ""

set netjig_prog $env(FREESWANSRCDIR)/testing/utils/uml_netjig/uml_netjig

spawn $netjig_prog --cmdproto -t $netjig_debug_opt 
set netjig1 $spawn_id

newswitch $netjig1 public
newswitch $netjig1 east
newswitch $netjig1 west
newswitch $netjig1 northpublic
newswitch $netjig1 southpublic

foreach host $argv {
    system "$host single &"
}

puts "\nExit the netjig when you are done\n"

set timeout -1
interact -reset -i $netjig1 

foreach host $argv {
    system "uml_mconsole $host halt"
}






