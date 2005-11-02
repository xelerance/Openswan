# NOTE: this is shared by a number of tests
# NOTE: this is also used to finalize east
: ==== cut ====
cat /tmp/pluto.log
ipsec look
/testing/pluto/bin/check-for-core
: ==== tuc ====

: ==== start ====

