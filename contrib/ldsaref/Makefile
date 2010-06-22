OPENSWANSRCDIR=../..
-include ${OPENSWANSRCDIR}/Makefile.inc
CFLAGS += -I${OPENSWANSRCDIR}/include

SOURCE=saref.c
TARGET=libsaref.so

${TARGET}: ${SOURCE}
	$(CC) ${CFLAGS} -fPIC -o $@ -shared -ldl ${SOURCE}

.PHONY: clean
clean:
	rm -f *~ ${TARGET}
