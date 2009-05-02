TESTNAME=modtest-noipcomp-01
TEST_TYPE=module_compile
TEST_PURPOSE=goal

KERNEL_VERSION=uml
KERNEL_NAME=linus

MODULE_DEF_INCLUDE=config-noipcomp.h
MODULE_DEFCONFIG=defconfig-noipcomp

ARCH=um
SUBARCH=`uname -m`

