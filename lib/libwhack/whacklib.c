/* Openswan command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004-2006  Michael Richardson <mcr@xelerance.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <openswan.h>
#include <stdarg.h>

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "whack.h"
#include "oswlog.h"

#include "secrets.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"

struct whackpacker {
    struct whack_message *msg;
    unsigned char        *str_roof;
    unsigned char        *str_next;
    int                   n;
    int                   cnt;
};

/*
 * The WhackMessage consists of a map embedded into an array.
 * This is done so that the initial ~8 bytes are typically identical.
 *
 * Some CDDL:
 *   whackmessage = [ magic:    0x77686B1F,
 *                    action:   uint,
 *                    whackdetails: WhackDetails ]
 *
 *   action //=       whack_status
 *   action //=       whack_shutdown
 *   action //=       whack_options
 *   action //=       whack_connection
 *
 *   WhackDetails //= ...
 *
 */

#define OK(x) ugh = (x); if(ugh) goto bad
#define CborSignatureTag 55799
#define CborOpenSwanTag  0x4f50534e

enum whack_cbor_attributes {
      WHACK_OPT_NAME = 1,
      WHACK_OPT_DEBUGGING = 2,
      WHACK_OPT_ASYNC
};

static void whack_cbor_encode_empty_map(QCBOREncodeContext *qec)
{
  QCBOREncode_OpenMap(qec);
  QCBOREncode_CloseMap(qec);
}

static err_t whack_cbor_magic_header(QCBOREncodeContext *qec)
{
  UsefulBufC bor = UsefulBuf_FROM_SZ_LITERAL("BOR");
  QCBOREncode_AddTag(qec, CborSignatureTag);
  QCBOREncode_AddTag(qec, CborOpenSwanTag);
  QCBOREncode_AddBytes(qec, bor);
  return NULL;
}

err_t whack_cbor_encode_msg(struct whack_message *wm, unsigned char *buf, size_t *plen)
{
  size_t outlen;
  QCBOREncodeContext qec;
  err_t ugh= NULL;
  QCBORError e;

  UsefulBuf into = {buf, (unsigned long)*plen};
  QCBOREncode_Init(&qec, into);

  OK(whack_cbor_magic_header(&qec));

  QCBOREncode_OpenArray(&qec);
  if(wm->whack_status) {
    QCBOREncode_AddInt64(&qec, WHACK_STATUS);
    whack_cbor_encode_empty_map(&qec);
    goto end;
  }

  if(wm->whack_shutdown) {
    QCBOREncode_AddInt64(&qec, WHACK_SHUTDOWN);
    whack_cbor_encode_empty_map(&qec);
    goto end;
  }

  if(wm->whack_options) {
    QCBOREncode_AddInt64(&qec, WHACK_OPTIONS);
  } else if (wm->whack_connection) {
    QCBOREncode_AddInt64(&qec, WHACK_CONNECTION);
  }

  QCBOREncode_OpenMap(&qec);

  /* really, should set each flag seperately, by name! */
  QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_DEBUGGING, wm->debugging);
  QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_ASYNC, wm->whack_async);

  if(wm->name) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_NAME, wm->name);
  }

#if 0

	|| !pack_str(wp, &wp->msg->left.id)     /* string 2 */
	|| !pack_str(wp, &wp->msg->left.cert)   /* string 3 */
	|| !pack_str(wp, &wp->msg->left.ca)     /* string 4 */
	|| !pack_str(wp, &wp->msg->left.groups) /* string 5 */
	|| !pack_str(wp, &wp->msg->left.updown) /* string 6 */
    	|| !pack_str(wp, &wp->msg->left.virt)    /* string 7 */
	|| !pack_str(wp, &wp->msg->right.id)    /* string 8 */
    	|| !pack_str(wp, &wp->msg->right.cert)  /* string 9 */
    	|| !pack_str(wp, &wp->msg->right.ca)    /* string 10 */
    	|| !pack_str(wp, &wp->msg->right.groups)/* string 11 */
	|| !pack_str(wp, &wp->msg->right.updown)/* string 12 */
    	|| !pack_str(wp, &wp->msg->right.virt)  /* string 13 */
	|| !pack_str(wp, &wp->msg->keyid)       /* string 14 */
	|| !pack_str(wp, &wp->msg->myid)        /* string 15 */
    	|| !pack_str(wp, &wp->msg->ike)         /* string 16 */
    	|| !pack_str(wp, &wp->msg->esp)         /* string 17 */
    	|| !pack_str(wp, &wp->msg->tpmeval)     /* string 18 */
    	|| !pack_str(wp, &wp->msg->left.xauth_name)    /* string 19 */
    	|| !pack_str(wp, &wp->msg->right.xauth_name)   /* string 20 */
    	|| !pack_str(wp, &wp->msg->connalias)   /* string 21 */
    	|| !pack_str(wp, &wp->msg->left.host_addr_name)    /* string 22 */
    	|| !pack_str(wp, &wp->msg->right.host_addr_name)   /* string 23 */
	|| !pack_str(wp, &wp->msg->string1)                /* string 24 */
	|| !pack_str(wp, &wp->msg->string2)                /* string 25 */
	|| !pack_str(wp, &wp->msg->string3)                /* string 26 */
	|| !pack_str(wp, &wp->msg->string4)                /* string 27: was dnshostname*/
	|| !pack_str(wp, &wp->msg->policy_label) /* string 28 */
	|| wp->str_roof - wp->str_next < (ptrdiff_t)wp->msg->keyval.len)    /* chunk (sort of string 28) */
    {
	ugh = "too many bytes of strings to fit in message to pluto";
	return ugh;
    }

    if(wp->msg->keyval.ptr)
    {
      if (wp->str_roof - wp->str_next < (ptrdiff_t)wp->msg->keyval.len) {
        return "no space for public key";
      }
      memcpy(wp->str_next, wp->msg->keyval.ptr, wp->msg->keyval.len);
      //log_ckaid("whack msg: %s", (unsigned char *)wp->str_next, wp->msg->keyval.len);
    }
    wp->msg->keyval.ptr = NULL;
    wp->str_next += wp->msg->keyval.len;

    return ugh;

#endif

    QCBOREncode_CloseMap(&qec);

 end:
    QCBOREncode_CloseArray(&qec);

    /* close the array */
    e = QCBOREncode_FinishGetSize(&qec, &outlen);
    if(e != QCBOR_SUCCESS) {
      ugh = "encoding failed";
      return ugh;
    }

    if(plen) {
      *plen = outlen;
    }
    return NULL;

 bad:
    return "CBOR encoding error";
}

err_t whack_cbor_decode_msg(struct whack_message *wm, unsigned char *buf, size_t buf_len)
{
  return "UGH";
}

#if 0
/**
 * Unpack a message whack received
 *
 * @param wp The whack message
 * @return err_t
 */
err_t unpack_whack_msg (struct whackpacker *wp)
{
    err_t ugh = NULL;

    if (wp->str_next > wp->str_roof)
    {
	ugh = builddiag("ignoring truncated message from whack: got %d bytes; expected %u"
			, (int) wp->n, (unsigned) sizeof(*wp->msg));
        return ugh;
    }

    if (!unpack_str(wp, &wp->msg->name)	          /* string 1 */
	|| !unpack_str(wp, &wp->msg->left.id)     /* string 2 */
	|| !unpack_str(wp, &wp->msg->left.cert)   /* string 3 */
	|| !unpack_str(wp, &wp->msg->left.ca)     /* string 4 */
	|| !unpack_str(wp, &wp->msg->left.groups) /* string 5 */
	|| !unpack_str(wp, &wp->msg->left.updown) /* string 6 */
    	|| !unpack_str(wp, &wp->msg->left.virt)   /* string 7 */
	|| !unpack_str(wp, &wp->msg->right.id)    /* string 8 */
    	|| !unpack_str(wp, &wp->msg->right.cert)  /* string 9 */
    	|| !unpack_str(wp, &wp->msg->right.ca)    /* string 10 */
	|| !unpack_str(wp, &wp->msg->right.groups)/* string 11 */
	|| !unpack_str(wp, &wp->msg->right.updown)/* string 12 */
    	|| !unpack_str(wp, &wp->msg->right.virt)  /* string 13 */
	|| !unpack_str(wp, &wp->msg->keyid)       /* string 14 */
	|| !unpack_str(wp, &wp->msg->myid)        /* string 15 */
    	|| !unpack_str(wp, &wp->msg->ike)         /* string 16 */
    	|| !unpack_str(wp, &wp->msg->esp)         /* string 17 */
    	|| !unpack_str(wp, &wp->msg->tpmeval)     /* string 18 */
    	|| !unpack_str(wp, &wp->msg->left.xauth_name)    /* string 19 */
    	|| !unpack_str(wp, &wp->msg->right.xauth_name)   /* string 20 */
    	|| !unpack_str(wp, &wp->msg->connalias)   /* string 21 */
    	|| !unpack_str(wp, &wp->msg->left.host_addr_name)    /* string 22 */
    	|| !unpack_str(wp, &wp->msg->right.host_addr_name)   /* string 23 */
	|| !unpack_str(wp, &wp->msg->string1)                /* string 24 */
	|| !unpack_str(wp, &wp->msg->string2)                /* string 25 */
	|| !unpack_str(wp, &wp->msg->string3)                /* string 26 */
	|| !unpack_str(wp, &wp->msg->string4)                /* string 27 was dnshostname*/
	|| !unpack_str(wp, &wp->msg->policy_label) /* string 28 */
	|| wp->str_roof - wp->str_next != (ptrdiff_t)wp->msg->keyval.len)	/* check chunk */
    {
	ugh = "message from whack contains bad string";
    }

    return ugh;
}

#endif

void
clear_end(struct whack_end *e)
{
    zero(e);
    e->id = NULL;
    e->cert = NULL;
    e->ca = NULL;
    e->updown = NULL;
    e->host_port = IKE_UDP_PORT;
}

int
whack_get_value(char *buf, size_t bufsize)
{
    int len;
    int try;

    fflush(stdout);
    usleep(20000); /* give fflush time for flushing - has to go through awk */

    try = 3;
    len = 0;
    while(try > 0 && len==0)
    {
	fprintf(stderr, "Enter username:   ");

	memset(buf, 0, bufsize);

	if(fgets(buf, bufsize, stdin) != buf) {
	    if(errno == 0) {
		fprintf(stderr, "Can not read password from standard in\n");
		exit(RC_WHACK_PROBLEM);
	    } else {
		perror("fgets value");
		exit(RC_WHACK_PROBLEM);
	    }
	}

	/* send the value to pluto, including \0, but fgets adds \n */
	len = strlen(buf);
	if(len == 0)
	{
	    fprintf(stderr, "answer was empty, retry\n");
	}

        try--;
    }

    if(len ==  0)
    {
	exit(RC_WHACK_PROBLEM);
    }

    return len;
}

size_t
whack_get_secret(char *buf, size_t bufsize)
{
    const char *secret;
    int len;

    fflush(stdout);
    usleep(20000); /* give fflush time for flushing */
    secret = getpass("Enter passphrase: ");
    secret = (secret == NULL) ? "" : secret;

    strncpy(buf, secret, bufsize);

    len = strlen(buf) + 1;

    return len;
}

