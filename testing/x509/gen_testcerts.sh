#!/bin/sh

if [ ! -f ./gen_testcerts.sh ]
then
	echo "for now only run from the directory that contains this script"
	exit
fi

# generate X509 certs for testing harness
# Paul Wouters <paul@xelerance.com>
#
# Work in Progress

# Clean
rm -f reqs/* certs/* keys/* newcerts/* crls/* pkcs12/* index.txt* serial*

# Prep
mkdir certs crls newcerts keys reqs pkcs12
touch index.txt
echo "01" > serial
export OPENSSL_CONF=./openssl.cnf

# Generate CA's
for cauth in ca otherca
do
openssl genrsa -passout pass:foobar -des3 -out keys/$cauth.key 1024 
openssl rsa -in keys/$cauth.key -out keys/$cauth.key -passin pass:foobar
# use defaults to ensure the same values for all certs based on openssl.cnf
expect  <<EOF
spawn openssl req -x509 -days 3650 -newkey rsa:1024 -keyout keys/$cauth.key -out certs/$cauth.crt -passin pass:foobar -passout pass:foobar
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "\n"
expect "Organizational"
send "\n"
expect "Common"
send "Xelerance test CA for $cauth\n"
expect "Email"
send "testing@xelerance.com\n"
expect ""
send "\n"
EOF
done

# Generate machine keys/certs
for machine in east west sunset sunrise north south pole park beet carrot nic japan bigkey revoked notyetvalid notvalidanymore signedbyotherca 
do
# generate host key/cert
expect  <<EOF
spawn openssl req -newkey rsa:1024 -passin pass:foobar -passout pass:foobar -keyout keys/$machine.key -out reqs/$machine.req
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "\n"
expect "Organizational"
send "\n"
expect "Common"
send "$machine.testing.xelerance.com\n"
expect "Email"
send "testing@xelerance.com\n"
expect "challenge"
send "\n"
expect "optional"
send "\n"
expect ""
send "\n"
EOF
# sign machine cert
openssl ca -batch -in reqs/$machine.req -days 365 -out certs/$machine.crt -notext -cert certs/ca.crt -keyfile keys/ca.key  -passin pass:foobar 
# package in pkcs#12
openssl pkcs12 -export -inkey keys/$machine.key -in certs/$machine.crt -name "$machine" -certfile certs/ca.cert -caname "Xelerance test CA for ca" -out pkcs12/$machine.p12 -passin pass:foobar -passout pass:foobar
done

# special cases

# large rsa key
expect  <<EOF
spawn openssl req -newkey rsa:2048 -passin pass:foobar -passout pass:foobar -keyout keys/bigkey.key -out reqs/bigkey.req
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "\n"
expect "Organizational"
send "\n"
expect "Common"
send "bigkey.testing.xelerance.com\n"
expect "Email"
send "testing@xelerance.com\n"
expect "challenge"
send "\n"
expect "optional"
send "\n"
expect ""
send "\n"
EOF
openssl ca -batch -in reqs/bigkey.req -days 365 -out certs/bigkey.crt -notext -cert certs/ca.crt -keyfile keys/ca.key  -passin pass:foobar 

# cert that is not yet valid

# cert that has expired

# signed by other ca
rm certs/signedbyotherca.crt
openssl ca -batch -in reqs/signedbyotherca.req -days 365 -out certs/signedbyotherca.crt -notext -cert certs/otherca.crt -keyfile keys/otherca.key  -passin pass:foobar

# wrong DN (Organisation is different)
expect  <<EOF
spawn openssl req -newkey rsa:1024 -passin pass:foobar -passout pass:foobar -keyout keys/wrongdnorg.key -out reqs/wrongdnorg.req
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "Traitors Inc\n"
expect "Organizational"
send "\n"
expect "Common"
send "wrongdnorg.testing.xelerance.com\n"
expect "Email"
send "testing@xelerance.com\n"
expect "challenge"
send "\n"
expect "optional"
send "\n"
expect ""
send "\n"
EOF
openssl ca -batch -in reqs/wrongdnorg.req -days 365 -out certs/wrongdnorg.crt -notext -cert certs/ca.crt -keyfile keys/ca.key  -passin pass:foobar

# wrong number of DN's
expect  <<EOF
spawn openssl req -newkey rsa:1024 -passin pass:foobar -passout pass:foobar -keyout keys/wrongdnnum.key -out reqs/wrongdnnum.req
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "\n"
expect "Organizational"
send ".\n"
expect "Common"
send "wrongdnnum.testing.xelerance.com\n"
expect "Email"
send "testing@xelerance.com\n"
expect "challenge"
send "\n"
expect "optional"
send "\n"
expect ""
send "\n"
EOF
openssl ca -batch -in reqs/wrongdnnum.req -days 365 -out certs/wrongdnnum.crt -notext -cert certs/ca.crt -keyfile keys/ca.key  -passin pass:foobar


# Unwise charachters
expect  <<EOF
spawn openssl req -newkey rsa:1024 -passin pass:foobar -passout pass:foobar -keyout keys/unwisechar.key -out reqs/unwisechar.req
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "\n"
expect "Organizational"
send "\n"
expect "Common"
send "unwisechar ~!@#$%^&*()-_=+;:/?<>.testing.xelerance.com\n"
expect "Email"
send "testing@xelerance.com\n"
expect "challenge"
send "\n"
expect "optional"
send "\n"
expect ""
send "\n"
EOF
openssl ca -batch -in reqs/unwisechar.req -days 365 -out certs/unwisechar.crt -notext -cert certs/ca.crt -keyfile keys/ca.key  -passin pass:foobar

# Space in CN
expect  <<EOF
spawn openssl req -newkey rsa:1024 -passin pass:foobar -passout pass:foobar -keyout keys/spaceincn.key -out reqs/spaceincn.req
expect "Country Name"
send "\n"
expect "State"
send "\n"
expect "Locality"
send "\n"
expect "Organization"
send "\n"
expect "Organizational"
send "\n"
expect "Common"
send "space invaders.testing.xelerance.com\n"
expect "Email"
send "testing@xelerance.com\n"
expect "challenge"
send "\n"
expect "optional"
send "\n"
expect ""
send "\n"
EOF
openssl ca -batch -in reqs/spaceincn.req -days 365 -out certs/spaceincn.crt -notext -cert certs/ca.crt -keyfile keys/ca.key  -passin pass:foobar

# Revoke and generate CRL
openssl ca -gencrl -crldays 15 -out crls/cacrl.pem  -keyfile keys/ca.key -cert certs/ca.crt -passin pass:foobar
openssl ca -gencrl -crldays 15 -out crls/othercacrl.pem  -keyfile keys/otherca.key -cert certs/otherca.crt -passin pass:foobar
openssl ca -revoke certs/revoked.crt -keyfile keys/ca.key -cert certs/ca.crt -passin pass:foobar
openssl crl -in crls/crl.pem -noout -text
