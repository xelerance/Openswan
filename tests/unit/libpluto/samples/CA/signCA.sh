#!/bin/sh

. ./setup.sh

commonName="/CN=Openswan Unit Testing Root CA"
DN=$countryName$stateOrProvinceName$localityName
DN=$DN$organizationName$organizationalUnitName$commonName

export subjectAltName=email:root@openswan.org
# 1220 days = three years plus 125 days

if [ ! -f $rootca/private/ca.key.$format ]; then
    echo GENERATING RSA KEY CA key
    openssl genpkey $pass -aes256
            -outform $format
            -out $rootca/private/ca.key.$format
    chmod 400 $rootca/private/ca.key.$format
    openssl pkey $passin -inform $format -in $rootca/private/ca.key.$format\
            -text -noout
fi

openssl req -config $cfgdir/openssl-root.cnf $passin \
     -set_serial 0x$(openssl rand -hex $sn)\
     -keyform $format -outform $format\
     -key $rootca/private/ca.key.$format -subj "$DN"\
     -new -x509 -days 1220 -sha256 -extensions v3_ca\
     -out $cadir/certs/ca.cert.$format
