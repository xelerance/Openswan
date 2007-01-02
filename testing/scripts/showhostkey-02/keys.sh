: ==== start ====
#!/bin/sh
TZ=GMT export TZ

ipsec showhostkey --file /testing/pluto/xauth-pluto-11/road.secrets --dump

: ==== end ====
