d() {
    expected=$1
    tee $expected.raw | sed -f canonicalize.sed | tee $expected.sane | diff -u - $expected | tee OUTPUT/$expected.diff
}

../refineconnection east.record	idlist.txt 2>&1 | d idlist-m-expected.txt
../refineconnection aggr.record	idlist.txt 2>&1 | d idlist-a-expected.txt


# Local Variables:
# compile-command: "./testlist.sh"
# End:
#

