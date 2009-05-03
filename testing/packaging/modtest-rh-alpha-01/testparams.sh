TESTNAME=modtest-rh-alpha-01
TEST_TYPE=module_compile
TEST_PURPOSE=goal

KERNEL_VERSION=2.4
KERNEL_NAME=rh

MODULE_DEF_INCLUDE=config-rh-alpha.h

# this is a horrible hack, sorry
HOSTARCH=`uname -m`
case $HOSTARCH in
	alpha) ;;
	*) exit 99;;	# means missing, cause we aren't alpha
esac

