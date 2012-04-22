LIBRESWANSRCDIR=../..
-include ${LIBRESWANSRCDIR}/Makefile.inc
CFLAGS += -I${LIBRESWANSRCDIR}/include

SOURCE=saref.c
TARGET=libsaref.so

${TARGET}: ${SOURCE}
	$(CC) ${CFLAGS} -fPIC -o $@ -shared -ldl ${SOURCE}

.PHONY: clean
clean:
	rm -f *~ ${TARGET}
