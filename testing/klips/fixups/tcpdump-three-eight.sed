s/icmp\([0-9 ]*\):/icmp:/
s/\(.*\)echo request seq .*\(.*\)/\1echo request (DF)\2/
s/\.isakmp/.500/g
s/^IP //
s/: IP /: /
