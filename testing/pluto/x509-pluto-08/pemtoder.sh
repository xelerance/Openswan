#!/bin/sh

openssl x509 -in ../../CA/west.uml.freeswan.org/west.uml.freeswan.org.cert -outform der -out westcert.der
