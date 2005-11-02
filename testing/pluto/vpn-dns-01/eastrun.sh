#SHOW=--show

: BAD/KEY - will fail
ipsec auto $SHOW --add    westnet-eastnet-bad-key
ipsec auto $SHOW --delete westnet-eastnet-bad-key

: TXT/BAD - will fail
ipsec auto $SHOW --add    westnet-eastnet-txt-bad
ipsec auto $SHOW --delete westnet-eastnet-txt-bad

: KEY/KEY
ipsec auto $SHOW --add    westnet-eastnet-key-key
ipsec auto $SHOW --delete westnet-eastnet-key-key

: KEY/TXT
ipsec auto $SHOW --add    westnet-eastnet-key-txt
ipsec auto $SHOW --delete westnet-eastnet-key-txt

: TXT/TXT
ipsec auto $SHOW --add    westnet-eastnet-txt-txt
ipsec auto $SHOW --delete westnet-eastnet-txt-txt

: TXT/KEY
ipsec auto $SHOW --add    westnet-eastnet-txt-key
ipsec auto $SHOW --delete westnet-eastnet-txt-key

