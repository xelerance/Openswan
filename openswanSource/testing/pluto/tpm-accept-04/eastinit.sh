: ==== start ====
TESTNAME=tpm-accept-04

TESTING=${TESTING-/testing}

mkdir -p /tmp/$TESTNAME
mkdir -p /tmp/$TESTNAME/ipsec.d/cacerts
mkdir -p /tmp/$TESTNAME/ipsec.d/crls
mkdir -p /tmp/$TESTNAME/ipsec.d/certs
mkdir -p /tmp/$TESTNAME/ipsec.d/private

cp /etc/ipsec.secrets                    /tmp/$TESTNAME

if [ -f ${TESTING}/pluto/$TESTNAME/east.secrets ]; then cat ${TESTING}/pluto/$TESTNAME/east.secrets >>/tmp/$TESTNAME/ipsec.secrets; fi

if [ -f ${TESTING}/pluto/$TESTNAME/east.tpm.tcl ]; then cp ${TESTING}/pluto/$TESTNAME/east.tpm.tcl /tmp/$TESTNAME/ipsec.d/tpm.tcl; fi

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS


PATH=/usr/local/sbin:$PATH
export PATH

rm -f /var/run/pluto/pluto.pid 

echo "Starting Openswan IPsec pluto"

(cd /tmp && /usr/local/libexec/ipsec/pluto --nofork --secretsfile /tmp/$TESTNAME/ipsec.secrets --ipsecdir /tmp/$TESTNAME/ipsec.d --use-nostack --uniqueids --nhelpers 0 --stderrlog 2>/tmp/pluto.log ) &

sleep 1

ipsec whack --listen


