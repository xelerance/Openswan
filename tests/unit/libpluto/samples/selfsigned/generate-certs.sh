#!/bin/sh

# this script generates a series of self-signed certificates for moon and dave.
# These are used in the lp52-55 series of tests.

echo
echo "Generating"

for HOST in moon dave
do
    cat >private/$HOST.conf <<END
[req]
distinguished_name = req_distinguished_name
req_extensions  = v3_req
x509_extensions = v3_ca

prompt = no

[req_distinguished_name]
C=CA
ST=Ontario
L=Ottawa
O=Xelerance Corporation
OU=Testing Devision
CN=dave.openswan.org/emailAddress=testing@xelerance.com

[v3_req]
subjectKeyIdentifier   = hash
basicConstraints       = CA:TRUE
#keyUsage               = keyusage

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:TRUE
#keyUsage               = keyusage
#subjectAltName         = subjectaltname
#issuerAltName          = issueraltname
END
    (
    set -e -x
    openssl genrsa -out private/${HOST}Key.pem 2048
    openssl req -config private/$HOST.conf -new \
        -key private/${HOST}Key.pem \
        -out private/$HOST.req
    openssl req -config private/$HOST.conf -x509 -days 1024 \
        -extensions v3_req -extensions v3_ca \
        -in private/$HOST.req \
        -key private/${HOST}Key.pem \
        -out certs/${HOST}Cert.pem
    )
done

echo
echo "Validating"

result=0
for HOST in moon dave
do
    k=$( openssl rsa -in private/${HOST}Key.pem -modulus -noout | md5sum )
    c=$( openssl x509 -in certs/${HOST}Cert.pem -modulus -noout | md5sum )

    if [ "$k" = "$c" ] ; then
        echo "$HOST -> OK"
    else
        echo "$HOST -> BAD"
        result=1
    fi
done

echo
exit $result
