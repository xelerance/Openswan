TESTNAME=modtest-nodebug-01
TEST_TYPE=module_compile
TEST_PURPOSE=goal

KERNEL_VERSION=uml
KERNEL_NAME=linus

MODULE_DEF_INCLUDE=config-nodebug.h
MODULE_DEFCONFIG=defconfig-nodebug

ARCH=um
SUBARCH=`uname -m`

