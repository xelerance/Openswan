#!/bin/sh
#
# cross compile example
#


#export PREFIX=/volquad/arm-4.0.2
export PREFIX=/usr/local/arm_tools
export DESTDIR=/tmp/openswan.arm

export ARCH=arm
export CC=$PREFIX/bin/arm-elf-gcc
export GCC=$PREFIX/bin/arm-elf-gcc
export LD=$PREFIX/bin/arm-elf-ld
export RANLIB=$PREFIX/bin/arm-elf-ranlib
export AR=$PREFIX/bin/arm-elf-ar
export AS=$PREFIX/bin/arm-elf-as
export STRIP=$PREFIX/bin/arm-elf-strip
export LD_LIBRARY_PATH=$PREFIX/lib/gcc-lib/arm-elf/3.0/
export PATH=$PATH:$PREFIX/bin
export USERCOMPILE="-O3 -g ${PORTDEFINE} -I'$PREFIX'/arm-elf/inc -L'$PREFIX'/lib/gcc-lib -DGCC_LINT -DLEAK_DETECTIVE -Dlinux -D__linux__"
export WERROR=' ' 

#now you can run:
# make programs
#and binaries will appear in OBJ.linux.$ARCH/
#and run:
# make install
#and the install will go into $DESTDIR/

# note: the arm_tools I had were so broken that some code failed to compile, this was ifdef'ed with BROKEN_COMPILER_HACK
# This relates to the PRINTF_LIKE(x) macro

# EXECUTABLE FILE FORMAT
#
# Some uClibc/busybox combinations use different executable files formats from ELF. This is configured during Linux kernel
# build. To convert the ELF binaries to BLTF, use elf2flt. The following script would convert all the binaries:

# for binary in `find $DESTDIR -type f |xargs file |grep "ELF 32-bit LSB executable" |sed "s/:.*$//"` ; do mv $binary $binary.elf ; elf2flt -z -v $binary.elf -o $binary ; done

