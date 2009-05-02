TESTNAME=modtest-link-01
TEST_TYPE=module_compile
TEST_PURPOSE=goal

KERNEL_VERSION=uml
KERNEL_NAME=linus

MODULE_DEF_INCLUDE=../../../packaging/linus/config-all.h
MODULE_DEFCONFIG=defconfig

KERNEL_PROCESS_FILE=examineunknowns.sh

ARCH=um
SUBARCH=`uname -m`

