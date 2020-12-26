/loaded CA cert/s/\(.*\)(.* bytes)/\1(CERT bytes)/
/loaded host cert/s/\(.*\)(.* bytes)/\1(CERT bytes)/
/loaded private key/s/\(.*\)(.* bytes)/\1(CERT bytes)/
/RC=0 List of X.509 End Certificates:/,/.*count: .*/d
/RC=0 List of X.509 CA Certificates:/,/.*count: .*/d

