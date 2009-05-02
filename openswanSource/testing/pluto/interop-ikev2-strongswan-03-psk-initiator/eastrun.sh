/usr/local/strongswan/sbin/ipsec up westnet--eastnet-ikev2
ping -c1 -I 192.0.2.254 192.0.1.254
/usr/local/strongswan/sbin/ipsec status
echo done
