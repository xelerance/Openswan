#!/bin/sh

. ./setup.sh

for HOSTNAME in dave carol moon bob
do
    intdir=$cadir/${HOSTNAME}cert

    clientemail=${HOSTNAME}@openswan.org

    #set -x
    if [ ! -f $intdir/private/$clientemail.key.$format ]; then
        openssl genpkey $pass \
            -out $intdir/private/$clientemail.key.$format
        chmod 400 $intdir/private/$clientemail.key.$format
        openssl pkey $passin -in $intdir/private/$clientemail.key.$format -text -noout
    fi

    commonName="/CN=${HOSTNAME}@openswan.org"
    DN=$countryName$stateOrProvinceName$localityName
    DN=$DN$organizationName$organizationalUnitName$commonName

    mkdir -p ${intdir}/csr

    export subjectAltName=email:${HOSTNAME}@openswan.org
    openssl req -config $cfgdir/openssl-root.cnf $passin \
            -key $intdir/private/$clientemail.key.$format \
            -subj "$DN" -new -sha256 -out $intdir/csr/$clientemail.csr.$format

    openssl rand -hex $sn > $cadir/serial # hex 8 is minimum, 19 is maximum

    openssl ca -config $cfgdir/openssl-root.cnf -days 830 \
            -extensions usr_cert -notext -md sha256 $passin \
            -in   $intdir/csr/$clientemail.csr.$format -batch\
            -out  $intdir/certs/$clientemail.cert.$format

done

