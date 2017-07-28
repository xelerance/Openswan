/*
 * test case for
 *    converting from text form of ike=
 *    to a structure to represent it.
 *
 * Copyright (C) 2017 Michael Richardson <mcr@xelerance.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include "openswan.h"
#include "ike_alg.h"
#include "plutoalg.h"

struct artab;
static void check(struct artab *r, char *buf, size_t n, err_t oops, int *status);
static void regress(char *pgm);

const char *progname;

void exit_tool(int x)
{
  exit(x);
}

/*
 - main - convert first argument to alginfo, or run regression
 */
int
main(int argc, char *argv[])
{
	char buf[1024];
	char buf2[1024];
	size_t n;
	size_t i;
	char *p = buf;
	char *p2 = buf2;
	char *pgm = argv[0];
        int   result;
	const char *oops;
	struct alg_info_ike *alg_info_ike;
        const  char *err;

        progname = argv[0];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {alginfo|-r}\n", pgm);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress(pgm);	/* should not return */
		fprintf(stderr, "%s: regress() returned?!?\n", pgm);
		exit(1);
	}

        alg_info_ike = alg_info_ike_create_from_str(argv[1],
                                                    &err);

        if(alg_info_ike == NULL) {
          fprintf(stderr
                  , "%s: unable to parse %s as algorithm identifier: %s\n"
                  , argv[0]
                  , argv[1], err);
          exit(1);
        }

	exit(0);
}

struct artab {
  char *ascii;		/* string to process */
  char *decode;		/* expected result after output */
  bool  err;            /* if TRUE, then err shall be set */
} atodatatab[] = {
  { "3des-md5-modp1024",
    "3DES_CBC(5)_000-MD5(1)_000-MODP1024(2); flags=-strict", FALSE,},
  { "aes-md5-modp1024",
    "AES_CBC(7)_000-MD5(1)_000-MODP1024(2); flags=-strict",  FALSE,},
  { "aes-sha1-modp1024",
    "AES_CBC(7)_000-SHA1(2)_000-MODP1024(2); flags=-strict", FALSE,},
  { "aes-sha1-modp1536",
    "AES_CBC(7)_000-SHA1(2)_000-MODP1536(5); flags=-strict", FALSE,},

  /* a modern definition from draft-ietf-ipsecme-rfc7321bis/ */
  { "aes256-sha256-prfsha256-modp2048",
    "AES_CBC(7)_256-SHA2(5)_000-PRFSHA2(5)-MODP2048(11); flags=-strict", FALSE,},
  { "foobar",           NULL, TRUE, },
  { NULL,		NULL, FALSE, },
};

static void			/* should not return at all, in fact */
regress(pgm)
char *pgm;
{
	int status = 0;
	struct artab *r;
	char buf[100];
	size_t n;
	struct alg_info_ike *alg_info_ike;
        const  char *err;

	for (r = atodatatab; r->ascii != NULL; r++) {
          err = NULL;
          alg_info_ike = alg_info_ike_create_from_str(r->ascii,
                                                      &err);
          if(r->err && err != NULL) {
              /* expected to fail, things are okay */
              continue;
          }

          if(err != NULL) {
            status++;
            fprintf(stderr, "failed to decode: %s, error: %s\n",
                    r->ascii, err);
            continue;
          }

          alg_info_snprint(buf, sizeof(buf), alg_info_ike, TRUE);

          if(r->decode != NULL && strcmp(r->decode, buf) != 0) {
            fprintf(stderr, "failed to decode: %s to %s. Got: %s\n",
                    r->ascii, r->decode, buf);
            status++;
            continue;
          }

	}
	exit(status);
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
