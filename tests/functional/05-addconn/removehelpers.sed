/^started helper/d
/^using .*urandom/d
s/starting up .* cryptographic helpers/starting up X cryptographic helpers/
/shutting down/d
s/adjusting ipsec.d to (.*)/adjusting ipsec.d to XX/
s/setting rootdir=(.*)/setting rootdir=YY/
s/opening file: (.*)/opening file: ZZ/
