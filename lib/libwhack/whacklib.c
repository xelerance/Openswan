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
#define CborIPv4Tag      260
#define CborIPv6Tag      261

/* values < 24 get encoded in one byte, < 256 in two bytes */
enum whack_cbor_attributes {
      WHACK_OPT_NAME = 1,
      WHACK_OPT_DEBUGGING = 2,
      WHACK_OPT_ASYNC = 128,
      WHACK_OPT_SET   = 129,
      WHACK_OPT_RECORDFILE=130,
      WHACK_OPT_MYID  = 131,
      WHACK_OPT_DELETE= 27,
      WHACK_OPT_DELETESTATE=8,
      WHACK_OPT_CRASHPEER=132,
      WHACK_OPT_LISTEN   =132,
      WHACK_OPT_UNLISTEN =133,
      WHACK_OPT_REREAD   =134,
      WHACK_OPT_LIST     =135,
      WHACK_OPT_PURGE_OCSP=136,
      WHACK_OPT_KEYID    = 137,
      WHACK_OPT_IKE      = 138,
      WHACK_OPT_ESP      = 139,
      WHACK_OPT_CONNALIAS= 140,
      WHACK_OPT_POLICYLABEL=141,
      WHACK_OPT_OPPO_MY_CLIENT = 142,
      WHACK_OPT_OPPO_PEER_CLIENT=143,

      WHACK_OPT_LEFT     = 3,
      WHACK_OPT_RIGHT    = 4,
      WHACK_OPT_END_ID   = 5,
      WHACK_OPT_END_CERT = 6,
      WHACK_OPT_END_CA   = 7,
      WHACK_OPT_END_GROUPS =8,
      WHACK_OPT_END_VIRT = 9,
      WHACK_OPT_END_XAUTH_NAME =137,       /* uncommon */
      WHACK_OPT_END_HOST_ADDRNAME = 10,
      WHACK_OPT_END_HOST_ADDR     = 11,
      WHACK_OPT_END_HOST_NEXTHOP  = 12,
      WHACK_OPT_END_HOST_SRCIP    = 13,
      WHACK_OPT_END_CLIENT        = 14,
      WHACK_OPT_KEYVAL            = 15,
};

#if 0
static void whack_cbor_encode_empty_map(QCBOREncodeContext *qec)
{
  QCBOREncode_OpenMap(qec);
  QCBOREncode_CloseMap(qec);
}
#endif

static err_t whack_cbor_magic_header(QCBOREncodeContext *qec)
{
  UsefulBufC bor = UsefulBuf_FROM_SZ_LITERAL("BOR");
  QCBOREncode_AddTag(qec, CborSignatureTag);
  QCBOREncode_AddTag(qec, CborOpenSwanTag);
  QCBOREncode_AddBytes(qec, bor);
  return NULL;
}

static void whack_cbor_encode_ipaddress(QCBOREncodeContext *qec, ip_address *addr)
{
  UsefulBufC ub;

  switch(ip_address_family(addr)) {
  case AF_INET:
    QCBOREncode_AddTag(qec, CborIPv4Tag);
    ub.ptr = (const void *)&addr->u.v4.sin_addr.s_addr;
    ub.len = 4;
    QCBOREncode_AddBytes(qec, ub);
    break;
  case AF_INET6:
    QCBOREncode_AddTag(qec, CborIPv6Tag);
    ub.ptr = (const void *)addr->u.v6.sin6_addr.s6_addr;
    ub.len = 16;
    QCBOREncode_AddBytes(qec, ub);
    break;
  }
}

static void whack_cbor_encode_some_ipaddress_ToMapN(QCBOREncodeContext *qec
                                                   , u_int32_t   link
                                                   , ip_address *addr)
{
  if(!ip_address_isany(addr)) {
    QCBOREncode_AddInt64(qec, link);
    whack_cbor_encode_ipaddress(qec, addr);
  }
}

static void whack_cbor_encode_some_ipsubnet_ToMapN(QCBOREncodeContext *qec
                                                  , u_int32_t   link
                                                  , ip_subnet  *net)
{
  ip_address *addr = &net->addr;

  if(!ip_address_isany(addr)) {
    QCBOREncode_OpenArrayInMapN(qec, link);
    QCBOREncode_AddInt64(qec, net->maskbits);
    whack_cbor_encode_ipaddress(qec, addr);
    QCBOREncode_CloseArray(qec);
  }
}

static void whack_cbor_encode_end(QCBOREncodeContext *qec, struct whack_end *we)
{
  if(we->id) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_ID, we->id);
  }
  if(we->cert) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_CERT, we->cert);
  }
  if(we->ca) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_CA, we->ca);
  }
  if(we->groups) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_GROUPS, we->groups);
  }
  if(we->virt) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_VIRT, we->virt);
  }
  if(we->xauth_name) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_XAUTH_NAME, we->xauth_name);
  }
  if(we->host_addr_name) {
    QCBOREncode_AddSZStringToMapN(qec, WHACK_OPT_END_HOST_ADDRNAME, we->host_addr_name);
  }

  /* host_addr */
  whack_cbor_encode_some_ipaddress_ToMapN(qec, WHACK_OPT_END_HOST_ADDR
                                         , &we->host_addr);

  /* host_nexthop */
  whack_cbor_encode_some_ipaddress_ToMapN(qec, WHACK_OPT_END_HOST_NEXTHOP
                                         , &we->host_nexthop);

  /* host_srcip */
  whack_cbor_encode_some_ipaddress_ToMapN(qec, WHACK_OPT_END_HOST_SRCIP
                                         , &we->host_srcip);

  /* client */
  whack_cbor_encode_some_ipsubnet_ToMapN(qec, WHACK_OPT_END_CLIENT
                                       , &we->client);

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

  QCBOREncode_OpenMap(&qec);
  if(wm->whack_status) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_STATUS);
    QCBOREncode_CloseMap(&qec);
  }

  if(wm->whack_shutdown) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_SHUTDOWN);
    QCBOREncode_CloseMap(&qec);
  }

  if(wm->whack_options) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_OPTIONS);
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_SET, wm->opt_set);
    if(wm->name) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_NAME, wm->name);
    }
    if(wm->string1) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_RECORDFILE, wm->string1);
    }
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_DEBUGGING, wm->debugging);
    QCBOREncode_CloseMap(&qec);
  }

  if (wm->whack_connection) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_CONNECTION);
    QCBOREncode_OpenMapInMapN(&qec, WHACK_OPT_LEFT);
    whack_cbor_encode_end(&qec, &wm->left);
    QCBOREncode_CloseMap(&qec);

    QCBOREncode_OpenMapInMapN(&qec, WHACK_OPT_RIGHT);
    whack_cbor_encode_end(&qec, &wm->right);
    QCBOREncode_CloseMap(&qec);

    QCBOREncode_CloseMap(&qec);
  }

  QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_ASYNC, wm->whack_async);

  if(wm->whack_myid) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_MYID, wm->myid);
  }

  if(wm->whack_delete) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_DELETE, wm->name);
  }

  if(wm->whack_deletestate) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_DELETESTATE, wm->whack_deletestateno);
  }

  if(wm->whack_crash) {
    /* open code the IPAddressToMap */
    QCBOREncode_AddInt64(&qec, WHACK_OPT_CRASHPEER);
    whack_cbor_encode_ipaddress(&qec, &wm->whack_crash_peer);
  }

  if(wm->whack_listen) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LISTEN, 1);
  }
  if(wm->whack_unlisten) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_UNLISTEN, 1);
  }
  if(wm->whack_reread) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_REREAD, wm->whack_reread);
  }
  if(wm->whack_list) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LIST, wm->whack_list);
  }
  if(wm->whack_purgeocsp) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_PURGE_OCSP, wm->whack_purgeocsp);
  }

  if(wm->whack_key) {
  }

  if(wm->whack_route) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_ROUTE);
    if(wm->name) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_NAME, wm->name);
    }
    QCBOREncode_CloseMap(&qec);
  }

  if(wm->whack_unroute) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_UNROUTE);
    if(wm->name) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_NAME, wm->name);
    }
    QCBOREncode_CloseMap(&qec);
  }
  if(wm->whack_initiate) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_INITIATE);
    if(wm->name) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_NAME, wm->name);
    }
    QCBOREncode_CloseMap(&qec);
  }
  if(wm->whack_oppo_initiate) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_INITIATE_OPPO);
    whack_cbor_encode_some_ipaddress_ToMapN(&qec, WHACK_OPT_OPPO_MY_CLIENT, &wm->oppo_my_client);
    whack_cbor_encode_some_ipaddress_ToMapN(&qec, WHACK_OPT_OPPO_PEER_CLIENT, &wm->oppo_peer_client);
    QCBOREncode_CloseMap(&qec);
  }

  if(wm->whack_terminate) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_TERMINATE);
    if(wm->name) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_NAME, wm->name);
    }
    QCBOREncode_CloseMap(&qec);
  }

  if(wm->whack_status) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_STATUS);
  }

  if(wm->keyid) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_KEYID, wm->keyid);
  }

  if(wm->ike) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_IKE, wm->ike);
  }
  if(wm->esp) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_ESP, wm->esp);
  }
  if(wm->connalias) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_CONNALIAS, wm->connalias);
  }

  if(wm->policy_label) {
    QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_POLICYLABEL, wm->policy_label);
  }

  if(wm->keyval.ptr && wm->keyval.len > 0) {
    UsefulBufC ub;
    ub.ptr = wm->keyval.ptr;
    ub.len = wm->keyval.len;
    QCBOREncode_AddBytesToMapN(&qec, WHACK_OPT_KEYVAL, ub);
  }

  QCBOREncode_CloseMap(&qec);

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

