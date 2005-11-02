 1098  ls
 1099  cd etc
 1100  ls
 1101  mkdir CA
 1102  cd CA
 1103  ls
 1104       openssl req -x509 -days 1460 -newkey rsa:2048 \\n                 -keyout caKey.pem -out caCert.pem
 1105  openssl genrsa -out ca.pem 1024
 1106       openssl req -x509 -days 1460 -key ca.pem \\n                 -keyout caKey.pem -out caCert.pem
 1107       openssl req -x509 -days 1460 -new -key ca.pem \\n                 -keyout caKey.pem -out caCert.pem
 1108  ls
 1109  openssl x509 -in caCert.pem -noout -text
 1110  pwd
 1111  ls
 1112  openssl ca -in ../../../east/etc/ipsec.d/private/east.req -days 730 -out ../../../east/etc/ipsec.d/eastCert.pem -notext
 1113  openssl ca -in ../../../east/etc/ipsec.d/private/east.req -days 730 -out ../../../east/etc/ipsec.d/eastCert.pem -notext -cakey ca.pem
