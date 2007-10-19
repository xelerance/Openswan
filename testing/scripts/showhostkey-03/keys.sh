: ==== start ====
#!/bin/sh
TZ=GMT export TZ

# test argument processing and help
ipsec showhostkey
ipsec showhostkey --help

ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --id east --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --id west --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --key
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --txt 192.168.1.3
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --x509self
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --x509req
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --x509cert

: ==== end ====
