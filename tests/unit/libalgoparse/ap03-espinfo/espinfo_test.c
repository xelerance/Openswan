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
#include "alg_info.h"
#include "oswlog.h"

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
	struct alg_info_esp *alg_info_esp;
        const  char *err;

        progname = argv[0];

        set_debugging(DBG_ALL);

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {alginfo|-r}\n", pgm);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress(pgm);	/* should not return */
		fprintf(stderr, "%s: regress() returned?!?\n", pgm);
		exit(1);
	}

        alg_info_esp = alg_info_esp_create_from_str(argv[1],
                                                    &err);

        if(alg_info_esp == NULL) {
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
    enum ikev2_trans_type_encr  encr_id;  unsigned int eklen;
    enum ikev2_trans_type_integ hash_id;
    enum ikev2_trans_type_dh    modp_id;
  char *decode;		/* expected result after output */
  bool  err;            /* if TRUE, then err shall be set */
} atodatatab[] = {
  { "3des-md5",
    IKEv2_ENCR_3DES, 0, IKEv2_AUTH_HMAC_MD5_96,
    0,
    "3des(3)_000-hmac_md5_96(1)_000; flags=-strict", FALSE,},
  { "3des_cbc-md5",          /* test out the alias for encr algorithms */
    IKEv2_ENCR_3DES, 0, IKEv2_AUTH_HMAC_MD5_96,
    0,
    "3des(3)_000-hmac_md5_96(1)_000; flags=-strict", FALSE,},
  { "aes-md5-modp1024",
    IKEv2_ENCR_AES_CBC, 128, IKEv2_AUTH_HMAC_MD5_96,
    OAKLEY_GROUP_MODP1024,
    "aes_cbc(12)_128-hmac_md5_96(1)_000-MODP1024(2); flags=-strict", FALSE,},
  { "aes-sha1",
    IKEv2_ENCR_AES_CBC, 128, IKEv2_AUTH_HMAC_SHA1_96,
    0,
    "aes_cbc(12)_128-hmac_sha1_96(2)_000; flags=-strict", FALSE,},
  { "aes-sha1-modp2048",
    IKEv2_ENCR_AES_CBC, 128, IKEv2_AUTH_HMAC_SHA1_96,
    OAKLEY_GROUP_MODP2048,
    "aes_cbc(12)_128-hmac_sha1_96(2)_000-MODP2048(14); flags=-strict", FALSE},

  /* a modern definition from draft-ietf-ipsecme-rfc7321bis/ */
  { "aes256-sha256",
    IKEv2_ENCR_AES_CBC, 256, IKEv2_AUTH_HMAC_SHA2_256_128,
    0,
    "aes_cbc(12)_256-hmac_sha2_256_128(12)_000; flags=-strict", FALSE,},
  { NULL, 0, 0,0,0,		NULL, FALSE, },
};

static void			/* should not return at all, in fact */
regress(pgm)
char *pgm;
{
	int status = 0;
	struct artab *r;
	char buf[100];
	size_t n;
	struct alg_info_esp *alg_info_esp;
        const  char *err;

	for (r = atodatatab; r->ascii != NULL; r++) {
          err = NULL;
          alg_info_esp = alg_info_esp_create_from_str(r->ascii,
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

          if(alg_info_esp->esp[0].transid != r->encr_id) {
              fprintf(stderr, "failed to decode: %s\n"
                      "  expected encr_id: %d\n"
                      "  got:              %d\n",
                      r->ascii, r->encr_id, alg_info_esp->esp[0].transid);
          }
          if(alg_info_esp->esp[0].enckeylen != r->eklen) {
              fprintf(stderr, "failed to decode: %s\n"
                      "  expected enc_len: %d\n"
                      "  got:              %d\n",
                      r->ascii, (int)r->eklen, (int)alg_info_esp->esp[0].enckeylen);
          }

          if(alg_info_esp->esp[0].auth!= r->hash_id) {
              fprintf(stderr, "failed to decode: %s\n"
                      "  expected hash_id: %d\n"
                      "  got:              %d\n",
                      r->ascii, r->hash_id, alg_info_esp->esp[0].auth);
          }

          alg_info_snprint(buf, sizeof(buf), ESPTOINFO(alg_info_esp));

          if(r->decode != NULL && strcmp(r->decode, buf) != 0) {
            fprintf(stderr, "failed to decode: %s\n"
                    "  to %s. \n"
                    "Got: %s\n",
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
