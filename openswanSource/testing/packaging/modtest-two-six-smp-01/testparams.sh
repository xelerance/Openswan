TESTNAME=modtest-two-six-smp-01
TEST_TYPE=module_compile
TEST_PURPOSE=goal

KERNEL_VERSION=uml
KERNEL_NAME=linus

MODULE_DEF_INCLUDE=config-smp.h
MODULE_DEFCONFIG=defconfig-smp

ARCH=um
SUBARCH=`uname -m`

