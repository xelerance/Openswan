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
/*
** DECODING
**
**
*/

/*
 * previously whack message strings all pointed to within the whack body,
 * but now they are alloc_bytes'ed.
 */
#define FREE_STRING(msg, name) if((msg)->name != NULL) { pfree((msg)->name); (msg)->name= NULL; }
void whack_free_msg(struct whack_message *msg)
{
     FREE_STRING(msg, name);
     FREE_STRING(msg, left.id);
     FREE_STRING(msg, left.cert);
     FREE_STRING(msg, left.ca);
     FREE_STRING(msg, left.groups);
     FREE_STRING(msg, left.virt);
     FREE_STRING(msg, left.xauth_name);
     FREE_STRING(msg, left.host_addr_name);
     FREE_STRING(msg, right.id);
     FREE_STRING(msg, right.cert);
     FREE_STRING(msg, right.ca);
     FREE_STRING(msg, right.groups);
     FREE_STRING(msg, right.virt);
     FREE_STRING(msg, right.xauth_name);
     FREE_STRING(msg, right.host_addr_name);
     FREE_STRING(msg, keyid);
     FREE_STRING(msg, myid);
     FREE_STRING(msg, ike);
     FREE_STRING(msg, esp);
     FREE_STRING(msg, connalias);
     FREE_STRING(msg, policy_label);
     FREE_STRING(msg, keyval.ptr);
     msg->keyval.len = 0;
}

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
  wm->whack_route = TRUE;
  whack_cbor_process_namemap(qdc, "route", wm, first);
}

void whack_cbor_process_unroute(QCBORDecodeContext *qdc
                              , struct whack_message *wm
                              , QCBORItem *first)
{
  wm->whack_unroute = TRUE;
  whack_cbor_process_namemap(qdc, "unroute", wm, first);
}

void whack_cbor_process_initiate(QCBORDecodeContext *qdc
                                 , struct whack_message *wm
                                 , QCBORItem *first)
{
  wm->whack_initiate = TRUE;
  whack_cbor_process_namemap(qdc, "initiate", wm, first);
}

void whack_cbor_process_terminate(QCBORDecodeContext *qdc
                                 , struct whack_message *wm
                                 , QCBORItem *first)
{
  wm->whack_terminate = TRUE;
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
        break;
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

      case WHACK_OPT_END_ADDR_FAMILY:
        wm->end_addr_family = item.val.int64;
        break;

      default:
        whack_cbor_consume_item(qdc, &item);
        break;
      }
    }

    if(uErr != QCBOR_SUCCESS) {
      CBOR_DEBUG("  connection at %d terminated with QCBOR error: %d\n", count
                 , uErr);
    }
}


/**
 * Unpack a message whack received
 *
 * @param wm   The whack message that will be filled in
 * @param buf  CBOR encoded whack message
 * @param plen A pointer to a size_t that contains the length of the input, and upon successful return, will be filled in with the amount of the data that was consumed.
 * @return err_t
 */
err_t whack_cbor_decode_msg(struct whack_message *wm, unsigned char *buf, size_t *plen)
{
    err_t ugh = "broken";
    UsefulBufC todecode = {buf, (unsigned long)*plen};
    QCBORDecodeContext qdc;
    QCBORItem   item;
    QCBORError  uErr;
    int elemCount = 0;
    bool foundMagic = FALSE;

    memset(wm, 0, sizeof(struct whack_message));
    unspecaddr(AF_INET, &wm->left.host_addr);
    unspecaddr(AF_INET, &wm->left.host_srcip);
    unspecaddr(AF_INET, &wm->right.host_addr);
    unspecaddr(AF_INET, &wm->right.host_srcip);
    unspecaddr(AF_INET, &wm->oppo_my_client);
    unspecaddr(AF_INET, &wm->oppo_peer_client);
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
        return builddiag("invalid whack key: %ld", item.label.int64);
      }

      elemCount--;
    }

    uErr = QCBORDecode_Finish(&qdc);
    if(uErr != QCBOR_SUCCESS && uErr != QCBOR_ERR_EXTRA_BYTES) {
      return builddiag("decoded failed with error %d", uErr);
    }

    if(elemCount != 0) {
      CBOR_DEBUG("elemCount: %d uErr: %d\n", elemCount, uErr);
      return "did not process message correctly";
    }

    /* find out from qdc how much space was used */
    size_t used = UsefulInputBuf_Tell(&qdc.InBuf);
    *plen = used;

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

