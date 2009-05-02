ipsec auto --route north--east-pass

ipsec auto --up  north--east-port3

telnet east-out 2 | wc -l
telnet east-out 3 | wc -l

echo done
