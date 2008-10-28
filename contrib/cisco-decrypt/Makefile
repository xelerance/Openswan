all:	cisco-decrypt

clean:
	rm cisco-decrypt

install:
	echo "cisco-decrypt is also installed as part of the vpnc packae"
	install -D cisco-decrypt /usr/local/bin/
	install -D cisco-decrypt.1 /usr/local/man/man1/

cisco-decrypt:
	cc -lgcrypt -o cisco-decrypt cisco-decrypt.c
