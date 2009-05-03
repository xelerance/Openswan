#
# Makefile for updating DNSSEC signatures on files.
#
# This uses GNU make-isms.
#

# 315360000 is ten years.
SIGNOPTIONS=-e now+315360000

# note that there seems to be something magic about the file that is
# here. MCR does not know what it is, so don't mess with this file
#ZONES=db...signed 
ZONES+=db.org..signed db.freeswan.org..signed 
ZONES+=db.uml.freeswan.org..signed 
ZONES+=db.arpa..signed db.in-addr.arpa..signed db.192.in-addr.arpa..signed
ZONES+=db.0.192.in-addr.arpa..signed
ZONES+=db.1.0.192.in-addr.arpa..signed
ZONES+=db.2.0.192.in-addr.arpa..signed
ZONES+=db.3.0.192.in-addr.arpa..signed
ZONES+=db.4.0.192.in-addr.arpa..signed
ZONES+=db.1.192.in-addr.arpa..signed
ZONES+=db.2.1.192.in-addr.arpa..signed
ZONES+=db.3.1.192.in-addr.arpa..signed
ZONES+=db.4.1.192.in-addr.arpa..signed
ZONES+=db.root-servers.net..signed

all: ${ZONES}

db.%.signed : db.% 
	dnssec-signzone ${SIGNOPTIONS} -o $* db.$* 


