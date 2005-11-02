TESTNAME=modtest-cryptoapi-02
TEST_TYPE=module_compile
TEST_PURPOSE=goal

KERNEL_VERSION=uml
KERNEL_NAME=linus

MODULE_DEF_INCLUDE=config-cryptoapi.h
MODULE_DEFCONFIG=defconfig-cryptoapi

ARCH=um
SUBARCH=`uname -m`

