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

#if 0
#define CBOR_DEBUG(fmt, ...)  printf(fmt, ##__VA_ARGS__)
#else
#define CBOR_DEBUG(fmt, ...)  do {} while(0)
#endif

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
      WHACK_OPT_CRASHPEER=132,
      WHACK_OPT_LISTEN   =133,
      WHACK_OPT_UNLISTEN =134,
      WHACK_OPT_REREAD   =135,
      WHACK_OPT_LIST     =136,
      WHACK_OPT_PURGE_OCSP=137,
      WHACK_OPT_IKE      = 139,
      WHACK_OPT_ESP      = 140,
      WHACK_OPT_CONNALIAS= 141,
      WHACK_OPT_POLICYLABEL=142,
      WHACK_OPT_OPPO_MY_CLIENT = 143,
      WHACK_OPT_OPPO_PEER_CLIENT=144,
      WHACK_OPT_DELETESTATE=145,

      WHACK_OPT_LEFT     = 3,
      WHACK_OPT_RIGHT    = 4,

      WHACK_OPT_LIFETIME_IKE = 146,
      WHACK_OPT_LIFETIME_IPSEC=147,
      WHACK_OPT_LIFETIME_REKEY_MARGIN=148,
      WHACK_OPT_LIFETIME_REKEY_FUZZ=149,
      WHACK_OPT_LIFETIME_REKEY_TRIES=150,
      WHACK_OPT_POLICY        = 151,
      WHACK_OPT_KEYVAL        = 15,
      WHACK_OPT_KEYID         = 16,
      WHACK_OPT_KEYALG        = 17,
};

enum whack_cbor_end_attr {
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

      WHACK_OPT_HOST_TYPE = 15,
      WHACK_OPT_KEYTYPE   = 16,
      WHACK_OPT_HAS_CLIENT= 17,
      WHACK_OPT_HAS_CLIENT_WILDCARD=18,
      WHACK_OPT_HAS_PORT_WILDCARD=19,
      WHACK_OPT_HOST_PORT=20,
      WHACK_OPT_PORT=138,
      WHACK_OPT_XAUTH_SERVER=139,
      WHACK_OPT_XAUTH_CLIENT=140,
      WHACK_OPT_MODECFG_SERVER=141,
      WHACK_OPT_MODECFG_CLIENT=142,
      WHACK_OPT_CERTPOLICY=143,
      WHACK_OPT_CERTTYPE=144,
      WHACK_OPT_TUNDEV=145
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

#define ADDIntIfNotZero(qec, tag, value) if(value != 0) QCBOREncode_AddInt64ToMapN(qec,tag,value)

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

  ADDIntIfNotZero(qec, WHACK_OPT_HOST_TYPE, we->host_type);
  ADDIntIfNotZero(qec, WHACK_OPT_KEYTYPE,   we->keytype);
  ADDIntIfNotZero(qec, WHACK_OPT_HAS_CLIENT, we->has_client);
  ADDIntIfNotZero(qec, WHACK_OPT_HAS_CLIENT_WILDCARD, we->has_client_wildcard);
  ADDIntIfNotZero(qec, WHACK_OPT_HAS_PORT_WILDCARD, we->has_port_wildcard);
  ADDIntIfNotZero(qec, WHACK_OPT_HOST_PORT, we->host_port);
  ADDIntIfNotZero(qec, WHACK_OPT_PORT,      we->protocol);
  ADDIntIfNotZero(qec, WHACK_OPT_XAUTH_SERVER, we->xauth_server);
  ADDIntIfNotZero(qec, WHACK_OPT_XAUTH_CLIENT, we->xauth_client);
  ADDIntIfNotZero(qec, WHACK_OPT_MODECFG_SERVER, we->modecfg_server);
  ADDIntIfNotZero(qec, WHACK_OPT_MODECFG_CLIENT, we->modecfg_client);
  ADDIntIfNotZero(qec, WHACK_OPT_CERTPOLICY, we->sendcert);
  ADDIntIfNotZero(qec, WHACK_OPT_CERTTYPE,   we->certtype);
  ADDIntIfNotZero(qec, WHACK_OPT_TUNDEV,     we->tundev);

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

    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_POLICY, wm->policy);
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LIFETIME_IKE, wm->sa_ike_life_seconds);
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LIFETIME_IPSEC, wm->sa_ipsec_life_seconds);
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LIFETIME_REKEY_MARGIN, wm->sa_rekey_margin);
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LIFETIME_REKEY_FUZZ, wm->sa_rekey_fuzz);
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LIFETIME_REKEY_TRIES, wm->sa_keying_tries);

    QCBOREncode_CloseMap(&qec);
  }

  if(wm->whack_async) {
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_ASYNC, wm->whack_async);
  }

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

  if(wm->whack_key) {
    QCBOREncode_OpenMapInMapN(&qec, WHACK_ADD_KEY);

    if(wm->keyid) {
      QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_KEYID, wm->keyid);
    }

    if(wm->keyval.ptr && wm->keyval.len > 0) {
      UsefulBufC ub;
      ub.ptr = wm->keyval.ptr;
      ub.len = wm->keyval.len;
      QCBOREncode_AddBytesToMapN(&qec, WHACK_OPT_KEYVAL, ub);
    }
    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KEYALG, wm->pubkey_alg);
    QCBOREncode_CloseMap(&qec);
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


/*
** DECODING
**
**
*/

void whack_cbor_string2c(QCBORDecodeContext *qdc, QCBORItem *item, char **where)
{
  if(*where) pfree(*where);
  *where = alloc_bytes(item->val.string.len+1, "whack string");
  memcpy(*where, item->val.string.ptr, item->val.string.len);
  (*where)[item->val.string.len]='\0';
}

/* this routine consumes an item, recursing into the content to get it all */
void whack_cbor_consume_itemX(QCBORDecodeContext *qdc, QCBORItem *oitem, int level)
{
    QCBORItem   item;
    QCBORError  uErr;

    memset(&item, 0, sizeof(item));

    /* the provide item will have the number of things to consume */

    /* do nothing if simple type, though */
    if(oitem->uDataType != QCBOR_TYPE_MAP
       && oitem->uDataType != QCBOR_TYPE_ARRAY) return;

    CBOR_DEBUG("  [%u] nesting start: %d\n", level, oitem->uNextNestLevel);
    while((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS
          && oitem->uNextNestLevel < item.uNextNestLevel) {

      CBOR_DEBUG("  [%u]   %u type: %d data:%ld nesting: %d->%d\n"
             , level
             , oitem->uNextNestLevel
             , item.uDataType
             , item.label.int64
             , item.uNestingLevel, item.uNextNestLevel);
      whack_cbor_consume_itemX(qdc, &item, level+1);
    }
    return;
}

/* this routine consumes an item, recursing into the content to get it all */
void whack_cbor_consume_item(QCBORDecodeContext *qdc, QCBORItem *oitem)
{
  whack_cbor_consume_itemX(qdc, oitem, 1);
}

void whack_cbor_decode_ipaddress(QCBORDecodeContext *qdc
                            , const char *endtype
                            , QCBORItem *first
                            , ip_address *ip)
{
  if(first->uDataType != QCBOR_TYPE_BYTE_STRING) {
    whack_cbor_consume_itemX(qdc, first, 1);
    return;
  }

  int len = first->val.string.len;
  const unsigned char *bytes = first->val.string.ptr;
  memset(ip, 0, sizeof(*ip));

  switch(QCBORDecode_GetNthTag(qdc, first, 0)) {
  case CborIPv4Tag:
    ip_address_family(ip) = AF_INET;
    if(len > 4) len = 4;
    memcpy((void *)&ip->u.v4.sin_addr.s_addr, bytes, len);
    break;
  case CborIPv6Tag:
    ip_address_family(ip) = AF_INET6;
    if(len > 16) len = 16;
    memcpy((void *)ip->u.v6.sin6_addr.s6_addr, bytes, len);
    break;
  }
}

void whack_cbor_decode_ipsubnet(QCBORDecodeContext *qdc
                                , const char *endtype
                                , QCBORItem *first
                                , ip_subnet *ipn)
{
    QCBORItem   item;
    QCBORError  uErr;
    if(first->uDataType != QCBOR_TYPE_ARRAY) {
      whack_cbor_consume_itemX(qdc, first, 1);
      return;
    }

    if((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS) {
      ipn->maskbits = item.val.int64;
    }

    if(uErr != QCBOR_SUCCESS
       || first->uNextNestLevel > item.uNextNestLevel) {
      return;
    }

    if((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS) {
      whack_cbor_decode_ipaddress(qdc, endtype, &item, &ipn->addr);
    }

    /* here we really need to eat the rest of the array? */
    //whack_cbor_consume_itemX(qdc, &item, 1);

    return;
}


void whack_cbor_process_namemap(QCBORDecodeContext *qdc
                                , const char *thingtype
                                , struct whack_message *wm
                                , QCBORItem *first)
{
    QCBORItem   item;
    QCBORError  uErr;
    int count = first->val.uCount;

    /* must be a MAP within the connection */
    if(first->uDataType != QCBOR_TYPE_MAP) return;

    /* now process these items */
    while(count-- > 0
          && ((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS)) {

      CBOR_DEBUG("    %s %d key: %ld value_type: %d\n", thingtype, count
             , item.label.int64
             , item.uDataType);
      switch(item.label.int64) {
      case WHACK_OPT_NAME:
        whack_cbor_string2c(qdc, &item, &wm->name);
        break;
      default:
        whack_cbor_consume_item(qdc, &item);
        break;
      }
    }
}

void whack_cbor_process_route(QCBORDecodeContext *qdc
                              , struct whack_message *wm
                              , QCBORItem *first)
{
  whack_cbor_process_namemap(qdc, "route", wm, first);
}

void whack_cbor_process_unroute(QCBORDecodeContext *qdc
                              , struct whack_message *wm
                              , QCBORItem *first)
{
  whack_cbor_process_namemap(qdc, "unroute", wm, first);
}

void whack_cbor_process_initiate(QCBORDecodeContext *qdc
                                 , struct whack_message *wm
                                 , QCBORItem *first)
{
  whack_cbor_process_namemap(qdc, "initiate", wm, first);
}

void whack_cbor_process_terminate(QCBORDecodeContext *qdc
                                 , struct whack_message *wm
                                 , QCBORItem *first)
{
  whack_cbor_process_namemap(qdc, "terminate", wm, first);
}


void whack_cbor_process_initiate_oppo(QCBORDecodeContext *qdc
                                      , struct whack_message *wm
                                      , QCBORItem *first)
{
    QCBORItem   item;
    QCBORError  uErr;
    int count = first->val.uCount;
    const char *thingtype = "oppo";

    /* must be a MAP within the connection */
    if(first->uDataType != QCBOR_TYPE_MAP) return;

    /* now process these items */
    while(count-- > 0
          && ((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS)) {

      CBOR_DEBUG("    %s %d key: %ld value_type: %d\n", thingtype, count
             , item.label.int64
             , item.uDataType);
      switch(item.label.int64) {
      case WHACK_OPT_OPPO_MY_CLIENT:
        whack_cbor_decode_ipaddress(qdc, thingtype, &item, &wm->oppo_my_client);
        break;
      case WHACK_OPT_OPPO_PEER_CLIENT:
        whack_cbor_decode_ipaddress(qdc, thingtype, &item, &wm->oppo_peer_client);
        break;
      default:
        whack_cbor_consume_item(qdc, &item);
        break;
      }
    }

}

void whack_cbor_process_end(QCBORDecodeContext *qdc
                            , const char *endtype
                            , struct whack_end *end
                            , QCBORItem *first)
{
    QCBORItem   item;
    QCBORError  uErr;
    int count = first->val.uCount;

    /* must be a MAP within the connection */
    if(first->uDataType != QCBOR_TYPE_MAP) return;

    CBOR_DEBUG("processing %s end: %ld count: %d\n", endtype, first->label.int64, count);

    /* now process these items */
    while(count-- > 0
          && ((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS)) {

      CBOR_DEBUG("    %s %d key: %ld value_type: %d\n", endtype, count
             , item.label.int64
             , item.uDataType);
      switch(item.label.int64) {
      case WHACK_OPT_END_ID:
        whack_cbor_string2c(qdc, &item, &end->id);
        break;
      case WHACK_OPT_END_CERT:
        whack_cbor_string2c(qdc, &item, &end->cert);
        break;
      case WHACK_OPT_END_CA:
        whack_cbor_string2c(qdc, &item, &end->ca);
        break;
      case WHACK_OPT_END_GROUPS:
        whack_cbor_string2c(qdc, &item, &end->groups);
        break;
      case WHACK_OPT_END_VIRT:
        whack_cbor_string2c(qdc, &item, &end->virt);
        break;
      case WHACK_OPT_END_XAUTH_NAME:
        whack_cbor_string2c(qdc, &item, &end->xauth_name);
        break;
      case WHACK_OPT_END_HOST_ADDRNAME:
        whack_cbor_string2c(qdc, &item, &end->host_addr_name);
        break;
      case WHACK_OPT_END_HOST_ADDR:
        whack_cbor_decode_ipaddress(qdc, endtype, &item, &end->host_addr);
        break;
      case WHACK_OPT_END_HOST_NEXTHOP:
        whack_cbor_decode_ipaddress(qdc, endtype, &item, &end->host_nexthop);
        break;
      case WHACK_OPT_END_HOST_SRCIP:
        whack_cbor_decode_ipaddress(qdc, endtype, &item, &end->host_srcip);
        break;
      case WHACK_OPT_END_CLIENT:
        whack_cbor_decode_ipsubnet(qdc, endtype, &item, &end->client);
        break;
      case WHACK_OPT_HOST_TYPE:
        end->host_type=item.val.int64;
        break;
      case WHACK_OPT_KEYTYPE:
        end->keytype= item.val.int64;
        break;
      case WHACK_OPT_HAS_CLIENT:
        end->has_client= item.val.int64;
        break;
      case WHACK_OPT_HAS_CLIENT_WILDCARD:
        end->has_client_wildcard= item.val.int64;
        break;
      case WHACK_OPT_HAS_PORT_WILDCARD:
        end->has_port_wildcard= item.val.int64;
        break;
      case WHACK_OPT_HOST_PORT:
        end->host_port = item.val.int64;
        break;
      case WHACK_OPT_PORT:
        end->protocol= item.val.int64;
        break;
      case WHACK_OPT_XAUTH_SERVER:
        end->xauth_server= item.val.int64;
        break;
      case WHACK_OPT_XAUTH_CLIENT:
        end->xauth_client= item.val.int64;
        break;
      case WHACK_OPT_MODECFG_SERVER:
        end->modecfg_server= item.val.int64;
        break;
      case WHACK_OPT_MODECFG_CLIENT:
        end->modecfg_client= item.val.int64;
        break;
      case WHACK_OPT_CERTPOLICY:
        end->sendcert= item.val.int64;
        break;
      case WHACK_OPT_CERTTYPE:
        end->certtype= item.val.int64;
        break;
      case WHACK_OPT_TUNDEV:
        end->tundev= item.val.int64;
        break;
      default:
        whack_cbor_consume_item(qdc, &item);
        break;
      }
    }
}

void whack_cbor_process_addkey(QCBORDecodeContext *qdc
                               , struct whack_message *wm
                               , QCBORItem *first)
{
    QCBORItem   item;
    QCBORError  uErr;
    int count = first->val.uCount;

    /* must be a MAP within the connection */
    if(first->uDataType != QCBOR_TYPE_MAP) return;

    CBOR_DEBUG("processing tag: %ld count: %d\n", first->label.int64, count);

    /* now process these items */
    while(count-- > 0
          && ((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS)) {

      CBOR_DEBUG("  %d key: %ld value_type: %d\n", count
             , item.label.int64
             , item.uDataType);
      switch(item.label.int64) {
      case WHACK_OPT_KEYVAL:
        wm->whack_addkey = TRUE;
        wm->keyval.ptr = clone_bytes(item.val.string.ptr, item.val.string.len, "whack keyval");
        wm->keyval.len = item.val.string.len;
        break;

      case WHACK_OPT_KEYALG:
        wm->pubkey_alg = item.val.int64;
        break;

      case WHACK_OPT_KEYID:
        whack_cbor_string2c(qdc, &item, &wm->keyid);
        break;

      default:
        whack_cbor_consume_item(qdc, &item);
        return;
      }
    }
}

void whack_cbor_process_connection(QCBORDecodeContext *qdc
                                   , struct whack_message *wm
                                   , QCBORItem *first)
{
    QCBORItem   item;
    QCBORError  uErr;
    int count = first->val.uCount;

    /* must be a MAP within the connection */
    if(first->uDataType != QCBOR_TYPE_MAP) return;

    CBOR_DEBUG("processing tag: %ld count: %d\n", first->label.int64, count);

    /* now process these items */
    while(count-- > 0
          && ((uErr = QCBORDecode_GetNext(qdc, &item)) == QCBOR_SUCCESS)) {

      CBOR_DEBUG("  %d key: %ld value_type: %d\n", count
             , item.label.int64
             , item.uDataType);
      switch(item.label.int64) {
      case WHACK_OPT_LEFT:
        whack_cbor_process_end(qdc, "left", &wm->left, &item);
        break;

      case WHACK_OPT_RIGHT:
        whack_cbor_process_end(qdc, "right",&wm->right, &item);
        break;

      case WHACK_OPT_POLICY:
        wm->policy = item.val.int64;
        break;

      case WHACK_OPT_LIFETIME_IKE:
        wm->sa_ike_life_seconds = item.val.int64;
        break;

      case WHACK_OPT_LIFETIME_IPSEC:
        wm->sa_ipsec_life_seconds = item.val.int64;
        break;

      case WHACK_OPT_LIFETIME_REKEY_MARGIN:
        wm->sa_rekey_margin = item.val.int64;
        break;

      case WHACK_OPT_LIFETIME_REKEY_FUZZ:
        wm->sa_rekey_fuzz = item.val.int64;
        break;

      case WHACK_OPT_LIFETIME_REKEY_TRIES:
        wm->sa_keying_tries = item.val.int64;
        break;

      default:
        whack_cbor_consume_item(qdc, &item);
        return;
      }
    }
}

/**
 * Unpack a message whack received
 *
 * @param wp The whack message
 * @return err_t
 */
err_t whack_cbor_decode_msg(struct whack_message *wm, unsigned char *buf, size_t plen)
{
    err_t ugh = "broken";
    UsefulBufC todecode = {buf, (unsigned long)plen};
    QCBORDecodeContext qdc;
    QCBORItem   item;
    QCBORError  uErr;
    int elemCount = 0;
    bool foundMagic = FALSE;

    QCBORDecode_Init(&qdc, todecode, QCBOR_DECODE_MODE_NORMAL);

    uErr = QCBORDecode_GetNext(&qdc, &item);
    if(uErr != QCBOR_SUCCESS) {
      return "does not decode as CBOR";
    }

    /* now look for the magic number, and ignore it */
    if(item.uDataType == QCBOR_TYPE_BYTE_STRING && item.uNestingLevel == 0) {
      if(memcmp(item.val.string.ptr, "BOR", 3) == 0
         && QCBORDecode_GetNthTag(&qdc, &item, 0) == CborOpenSwanTag
         && QCBORDecode_GetNthTag(&qdc, &item, 1) == CborSignatureTag) {
        /* COOL, found Magic number */
        foundMagic = TRUE;
      }
    }

    /* is it okay for magic sequence to be omitted? */
    if(!foundMagic) {
      /* found something weird */
      return "missing magic tag";
    }

    /* now open the first Map */
    uErr = QCBORDecode_GetNext(&qdc, &item);
    if(uErr != QCBOR_SUCCESS ||
       item.uDataType != QCBOR_TYPE_MAP) {
      return "malformed map at level 0";
    }
    //whack_cbor_consume_item(&qdc, &item);
    //return "fun";

    /* keep track of how many items */
    elemCount = item.val.uCount;
    while(elemCount > 0
          && (uErr = QCBORDecode_GetNext(&qdc, &item)) == QCBOR_SUCCESS) {
      /* within the MAP, the labels are uLabelType, while the values are uDataType */
      if(item.uLabelType != QCBOR_TYPE_INT64) {
        return "map key must be integer";
      }
      CBOR_DEBUG("%u found map with labeled: %ld\n", elemCount, item.label.int64);
      switch(item.label.int64) {
      case WHACK_STATUS:
        wm->whack_status = TRUE;
        /* consume value, which is probably empty map */
        whack_cbor_consume_item(&qdc, &item);
        break;
      case WHACK_SHUTDOWN:
        wm->whack_shutdown = TRUE;
        whack_cbor_consume_item(&qdc, &item);
        break;

      case WHACK_OPTIONS:
        wm->whack_options  = TRUE;
        whack_cbor_consume_item(&qdc, &item);
        break;

      case WHACK_CONNECTION:
        wm->whack_connection = TRUE;
        whack_cbor_process_connection(&qdc, wm, &item);
        break;

      case WHACK_ADD_KEY:
        wm->whack_key  = TRUE;
        whack_cbor_process_addkey(&qdc, wm, &item);
       break;

      case WHACK_OPT_ASYNC:
        wm->whack_async = item.val.int64;
        break;

      case WHACK_OPT_MYID:
        whack_cbor_string2c(&qdc, &item, &wm->myid);
        break;

      case WHACK_OPT_DELETE:
        wm->whack_delete = TRUE;
        whack_cbor_string2c(&qdc, &item, &wm->name);
        break;

      case WHACK_OPT_DELETESTATE:
        wm->whack_deletestate = TRUE;
        wm->whack_deletestateno = item.val.int64;
        break;

      case WHACK_OPT_CRASHPEER:
        wm->whack_crash = TRUE;
        whack_cbor_decode_ipaddress(&qdc, "crash", &item, &wm->whack_crash_peer);
        break;

      case WHACK_OPT_LISTEN:
        wm->whack_listen = TRUE;
        break;

      case WHACK_OPT_UNLISTEN:
        wm->whack_unlisten = TRUE;
        break;

      case WHACK_OPT_REREAD:
        wm->whack_reread = item.val.int64;
        break;

      case WHACK_OPT_LIST:
        wm->whack_list = item.val.int64;
        break;

      case WHACK_OPT_PURGE_OCSP:
        wm->whack_list = item.val.int64;
        break;

      case WHACK_ROUTE:
        whack_cbor_process_route(&qdc, wm, &item);
        break;

      case WHACK_UNROUTE:
        whack_cbor_process_unroute(&qdc, wm, &item);
        break;

      case WHACK_INITIATE:
        whack_cbor_process_initiate(&qdc, wm, &item);
        break;

      case WHACK_INITIATE_OPPO:
        whack_cbor_process_initiate_oppo(&qdc, wm, &item);
        break;

      case WHACK_TERMINATE:
        whack_cbor_process_terminate(&qdc, wm, &item);
        break;

      case WHACK_OPT_IKE:
        whack_cbor_string2c(&qdc, &item, &wm->ike);
        break;

      case WHACK_OPT_ESP:
        whack_cbor_string2c(&qdc, &item, &wm->esp);
        break;

      case WHACK_OPT_CONNALIAS:
        whack_cbor_string2c(&qdc, &item, &wm->connalias);
        break;

      case WHACK_OPT_POLICYLABEL:
        whack_cbor_string2c(&qdc, &item, &wm->policy_label);
        break;

      default:
        return "invalid whack key";
      }

      elemCount--;
    }

    if(elemCount != 0) {
      CBOR_DEBUG("elemCount: %d uErr: %d\n", elemCount, uErr);
      return "did not process message correctly";
    }

    /* success */
    ugh = NULL;

    return ugh;
}

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

