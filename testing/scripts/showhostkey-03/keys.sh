: ==== start ====
#!/bin/sh
TZ=GMT export TZ

# Test ignoring of PSK's and XAUTH's and PIN's
ipsec showhostkey --dump

ipsec showhostkey --file /testing/pluto/scripts/showhostkey-03/multiple.secrets --left

: ==== end ====
