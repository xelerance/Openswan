#!/bin/sh

# HACK up the config file first

source ../../umlsetup.sh

sed -e "s,@BUILDTOP@,$BUILDTOP," nic/etc/openssl/openssl.cnf.in >nic/etc/openssl/openssl.cnf

for host in east west north
do
    if [ ! -r all/etc/ipsec.d/certs/${host}.crt ]
    then
	    openssl ca -config nic/etc/openssl/openssl.cnf -in $host/etc/ipsec.d/private/$host.req -days 730 -out all/etc/ipsec.d/certs/${host}.crt -notext -keyfile nic/etc/CA/private/cakey.pem
    fi

done

# now update the CRL list.
openssl ca -config nic/etc/openssl/openssl.cnf -gencrl -out all/etc/ipsec.d/crls/nic.pem

