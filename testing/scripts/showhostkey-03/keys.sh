: ==== start ====
#!/bin/sh
TZ=GMT export TZ

<<<<<<< HEAD:testing/scripts/showhostkey-03/keys.sh
# Test ignoring of PSK's and XAUTH's and PIN's
ipsec showhostkey --dump
=======
# test argument processing and help
ipsec showhostkey
ipsec showhostkey --help
>>>>>>> b443c04:testing/scripts/showhostkey-03/keys.sh

<<<<<<< HEAD:testing/scripts/showhostkey-03/keys.sh
ipsec showhostkey --file /testing/pluto/scripts/showhostkey-03/multiple.secrets --left
=======
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --id east --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --id west --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --left
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --right
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --key
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --txt 192.168.1.3
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --x509self
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --x509req
ipsec showhostkey --file /testing/baseconfigs/west/etc/ipsec.secrets-via.include --x509cert
>>>>>>> b443c04:testing/scripts/showhostkey-03/keys.sh

: ==== end ====
