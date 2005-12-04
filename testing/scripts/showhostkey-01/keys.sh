: ==== start ====
#!/bin/sh
TZ=GMT export TZ

ipsec showhostkey
ipsec showhostkey --left
ipsec showhostkey --right
ipsec showhostkey --txt 192.168.1.2
ipsec showhostkey --key
ipsec showhostkey --x509self
ipsec showhostkey --x509req
ipsec showhostkey --x509cert
ipsec showhostkey --help
ipsec showhostkey --id east --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --id east --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --id west --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --key
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --txt 192.168.1.3
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --x509self
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --x509req
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets --x509cert

: ==== end ====
