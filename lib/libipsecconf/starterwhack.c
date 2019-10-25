/* Openswan whack functions to communicate with pluto (whack.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ipsecconf/starterwhack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"

#include "socketwrapper.h"

#ifndef _OPENSWAN_H
#include <openswan.h>  /** FIXME: ugly include lines **/
#include "constants.h"
#endif

#include "oswalloc.h"
#include "oswlog.h"
#include "whack.h"
#include "id.h"
#include "secrets.h"
#include "sha2.h"

static void
update_ports(struct whack_message * m)
{
    int port;

    if (m->left.port != 0) {
        port = htons(m->left.port);
        setportof(port, &m->left.host_addr);
        setportof(port, &m->left.client.addr);
    }
    if (m->right.port != 0) {
        port = htons(m->right.port);
        setportof(port, &m->right.host_addr);
        setportof(port, &m->right.client.addr);
    }
}

static int
send_reply(int sock, char *buf, ssize_t len)
{
    /* send the secret to pluto */
    if (write(sock, buf, len) != len)
    {
	int e = errno;

	starter_log(LOG_LEVEL_ERR, "whack: write() failed (%d %s)\n",
		    e, strerror(e));
	return RC_WHACK_PROBLEM;
    }
    return 0;
}

int starter_whack_read_reply(int sock,
			     char xauthname[XAUTH_MAX_NAME_LENGTH],
			     char xauthpass[XAUTH_MAX_PASS_LENGTH],
			     int xauthnamelen,
			     int xauthpasslen)
{
	char buf[4097];	/* arbitrary limit on log line length */
	char *be = buf;
	int ret = 0;

	for (;;)
	{
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf)-1) - be);

		if (rl < 0)
		{
			int e = errno;

			fprintf(stderr, "whack: read() failed (%d %s)\n", e, strerror(e));
			return RC_WHACK_PROBLEM;
		}
		if (rl == 0)
		{
			if (be != buf)
				fprintf(stderr, "whack: last line from pluto too long or unterminated\n");
			break;
		}

		be += rl;
		*be = '\0';

		for (;;)
		{
		    char *le = strchr(ls, '\n');

		    if (le == NULL)
		    {
			/* move last, partial line to start of buffer */
			memmove(buf, ls, be-ls);
			be -= ls - buf;
			break;
		    }

		    le++;	/* include NL in line */
		    if(write(STDOUT_FILENO, ls, le - ls) == -1) {
			int e = errno;
			starter_log(LOG_LEVEL_ERR, "whack: write() failed (%d %s), and ignored.\n",
		    		e, strerror(e));
		    }

		    /* figure out prefix number
		     * and how it should affect our exit status
		     */
		    {
			unsigned long s = strtoul(ls, NULL, 10);

			switch (s)
			{
			case RC_COMMENT:
			case RC_LOG:
			    /* ignore */
			    break;
			case RC_SUCCESS:
			    /* be happy */
			    ret = 0;
			    break;

			case RC_ENTERSECRET:
				if(xauthpasslen==0) {
					xauthpasslen = whack_get_secret(xauthpass
								  , XAUTH_MAX_PASS_LENGTH);
				}
				if (xauthpasslen > XAUTH_MAX_PASS_LENGTH) { /* for input >= 128, xauthpasslen would be 129 */
					xauthpasslen = XAUTH_MAX_PASS_LENGTH;
					starter_log(LOG_LEVEL_ERR, "xauth password cannot be >= %d chars", XAUTH_MAX_PASS_LENGTH);
				}
				ret=send_reply(sock, xauthpass, xauthpasslen);
				if(ret!=0) return ret;
				break;

			case RC_XAUTHPROMPT:
				if(xauthnamelen==0) {
					xauthnamelen = whack_get_value(xauthname
								 , XAUTH_MAX_NAME_LENGTH);
				}
				if (xauthnamelen > XAUTH_MAX_NAME_LENGTH) { /* for input >= 128, xauthnamelen would be 129 */
					xauthnamelen = XAUTH_MAX_NAME_LENGTH;
					starter_log(LOG_LEVEL_ERR, "xauth name cannot be >= %s chars", XAUTH_MAX_NAME_LENGTH);
				}
				ret=send_reply(sock, xauthname, xauthnamelen);
				if(ret!=0) return ret;
				break;

			    /* case RC_LOG_SERIOUS: */
			default:
				/* pass through */
				ret = s;
				break;
			}
		    }
		    ls = le;
		}
	}
	return ret;
}

/* returns length of result... XXX unit test would be good here */
int serialize_whack_msg(struct whack_message *msg)
{
	struct whackpacker wp;
	ssize_t len;
	err_t ugh;

	/**
	 * Pack strings
	 */
        wp.cnt = 0;
	wp.msg = msg;
	wp.str_next = (unsigned char *)msg->string;
	wp.str_roof = (unsigned char *)&msg->string[sizeof(msg->string)];

	ugh = pack_whack_msg(&wp);

	if(ugh)
	{
	    starter_log(LOG_LEVEL_ERR, "send_wack_msg(): can't pack strings: %s", ugh);
	    return -1;
	}

	len = wp.str_next - (unsigned char *)msg;
        return len;
}

static int send_whack_msg(struct starter_config *cfg, struct whack_message *msg)
{
  if(cfg->send_whack_msg) {
    return cfg->send_whack_msg(cfg, msg);
  } else {
    starter_log(LOG_LEVEL_ERR, "no send_whack_msg function defined");
    return -1;
  }
}

static int send_whack_msg_to_socket(struct starter_config *cfg, struct whack_message *msg)
{
	struct sockaddr_un ctl_addr =
	    { .sun_family = AF_UNIX };
	int sock;
	ssize_t len;
	int ret;

	/* copy socket location */
	strncpy(ctl_addr.sun_path, cfg->ctlbase, sizeof(ctl_addr.sun_path));

        len = serialize_whack_msg(msg);
        if(len == -1) return -1;   /* already logged error */

	/**
	 * Connect to pluto ctl
	 */
	sock = safe_socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		starter_log(LOG_LEVEL_ERR, "socket() failed: %s", strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
		offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path))<0) {
		starter_log(LOG_LEVEL_ERR, "connect(pluto_ctl) failed: %s",
			strerror(errno));
		close(sock);
		return -1;
	}

	/**
	 * Send message
	 */
	if (write(sock, msg, len) != len) {
		starter_log(LOG_LEVEL_ERR, "write(pluto_ctl) failed: %s",
			strerror(errno));
		close(sock);
		return -1;
	}

	/**
	 * read reply
	 */
	{
		char xauthname[XAUTH_MAX_NAME_LENGTH];
		char xauthpass[XAUTH_MAX_PASS_LENGTH];

		ret = starter_whack_read_reply(sock, xauthname,xauthpass,0,0);
		close(sock);
	}

	return ret;
}

void init_whack_msg (struct whack_message *msg)
{
	memset(msg, 0, sizeof(struct whack_message));
	msg->magic = WHACK_MAGIC;
}

static char *connection_name (struct starter_conn *conn)
{
	/**
	 * If connection name is '%auto', create a new name like conn_xxxxx
	 */
	static char buf[32];
	if (strcmp(conn->name, "%auto")==0) {
		sprintf(buf, "conn_%ld", conn->id);
		return buf;
	}
	else {
		return conn->name;
	}
}

static char *split_dns_hostname(struct starter_conn *conn
                                , char *lr
                                , char *dnsname
                                , ip_address *host_addr)
{
  char *slash = strchr(dnsname, '/');
  ip_address tmp;
  err_t e;
  if(slash) {
    char *ip;
    *slash = '\0';
    slash++;

    ip = slash;
    slash = strchr(slash, '/');
    if(slash) {
      *slash = '\0';
      slash++;
    }
    /* now convert to IP address */
    e = ttoaddr(ip, 0, 0, &tmp);
    if(!e) {
      /* avoid trashing host_addr on error */
      *host_addr = tmp;
    } else {
      starter_log(LOG_LEVEL_DEBUG, "conn %s, %s= %dns hint(%s) failed to parse as IPv4/IPv6 address, ignored",
                  connection_name(conn), lr, ip);
    }
  }

  /* return first part as DNS name */
  return dnsname;
}


static int set_whack_end(struct starter_config *cfg
                          , struct starter_conn *conn
			  , char *lr
			  , struct whack_end *w
			  , struct starter_end *l)
{
	w->id = l->id;
	w->host_type = l->addrtype;

        /* may get overridden if IPHOSTNAME */
	w->host_addr_name = l->strings[KSCF_IP];
        anyaddr(l->end_addr_family, &w->host_addr);
        if(l->tunnel_addr_family == 0) {
          l->tunnel_addr_family = l->end_addr_family;
        }

	switch(l->addrtype) {
	case KH_DEFAULTROUTE:
		w->host_addr = cfg->dr;
		if(addrtypeof(&w->host_addr) == 0) {
			w->host_addr = *aftoinfo(AF_INET6)->any;
		}
		break;

	case KH_IPADDR:
	case KH_IFACE:
		w->host_addr = l->addr;
		break;

	case KH_IPHOSTNAME:
          /* go split the string up into DNS part, and one or more hints */
          w->host_addr_name = split_dns_hostname(conn, lr
                                                 , l->strings[KSCF_IP]
                                                 , &w->host_addr);
          break;

	case KH_OPPO:
	case KH_GROUP:
	case KH_OPPOGROUP:
		/* policy should have been set to OPPO */
		anyaddr(l->end_addr_family, &w->host_addr);
		break;

	case KH_ANY:
		anyaddr(l->end_addr_family, &w->host_addr);
		break;

        case KH_NOTSET:
          printf("%s: %s= end is not defined, conn not loaded\n", conn->name, lr);
                return -1;

	default:
          printf("%s %s: do something with host case: %d\n", conn->name, lr, l->addrtype);
		break;
	}

	switch(l->nexttype) {
	case KH_DEFAULTROUTE:
		w->host_nexthop = cfg->dnh;
		break;

	case KH_IPADDR:
		w->host_nexthop = l->nexthop;
		break;

	default:
          printf("%s %s: do something with nexthop case: %d\n", conn->name, lr, l->nexttype);
		break;

	case KH_NOTSET:  /* acceptable to not set nexthop */
		/* but, get the family set up right
		 * XXX the nexthop type has to get into the whack message!
		 *
		 */
		anyaddr(addrtypeof(&l->addr), &w->host_nexthop);
		break;
	}

	if(!isanyaddr(&l->sourceip)) {
		w->host_srcip = l->sourceip;
	}

	w->has_client = l->has_client;
	if (l->has_client) {
		w->client = l->subnet;
	}
	else {
		w->client.addr.u.v4.sin_family = l->tunnel_addr_family;
	}
	w->updown = l->strings[KSCF_UPDOWN];
	w->host_port = IKE_UDP_PORT;
	w->has_client_wildcard = l->has_client_wildcard;
	w->has_port_wildcard   = l->has_port_wildcard;

        if(l->rsakey1_type == PUBKEY_CERTIFICATE) {
          w->cert = l->cert;
          w->ca   = l->ca;
          if(l->options_set[KNCF_SENDCERT]) {
            w->sendcert = l->options[KNCF_SENDCERT];
          } else {
            w->sendcert = cert_alwayssend;
          }
        } else if(l->rsakey1_type == PUBKEY_PREEXCHANGED) {
          /* overloading w->cert and w->ca to avoid adding more useless
           * strings to whack structure. Wish it was JSON...
           */
          w->cert = l->rsakey1_ckaid;
          w->ca   = l->rsakey2_ckaid;
        }
	w->keytype = l->rsakey1_type;

	w->updown = l->updown;
	w->virt   = NULL;
	w->protocol = l->protocol;
	w->port = l->port;
	w->virt = l->virt;

	if(l->options_set[KNCF_XAUTHSERVER]) {
		w->xauth_server = l->options[KNCF_XAUTHSERVER];
	}
	if(l->options_set[KNCF_XAUTHCLIENT]) {
		w->xauth_client = l->options[KNCF_XAUTHCLIENT];
	}
	if(l->strings_set[KSCF_XAUTHUSERNAME]) {
		w->xauth_name = l->strings[KSCF_XAUTHUSERNAME];
	}
	if(l->options_set[KNCF_MODECONFIGSERVER]) {
		w->modecfg_server = l->options[KNCF_MODECONFIGSERVER];
	}
	if(l->options_set[KNCF_MODECONFIGCLIENT]) {
		w->modecfg_client = l->options[KNCF_MODECONFIGCLIENT];
	}
        return 0;
}


/*
 * returns 0 if a key needs to be sent
 * returns 1 if there was an error.
 * returns 2 if everything is fine, no key to send.
 */
int starter_whack_build_pkmsg(struct starter_config *cfg,
                              struct whack_message *msg,
                              struct starter_conn *conn,
                              struct starter_end *end,
                              unsigned int keynum,
                              enum pubkey_source key_type,
                              unsigned char *rsakey,
                              char *ckaid_buf, size_t ckaid_buf_len,
                              const char *lr)
{
  unsigned char keyspace[1024 + 4];
  size_t        keylen;
  const char *err;
  snprintf(ckaid_buf, ckaid_buf_len, "unknown");

  msg->whack_key = TRUE;
  msg->pubkey_alg = PUBKEY_ALG_RSA;
  if (end->id && rsakey) {
    msg->keyid = end->id;   /* msg->keyid will just borrow string  */

    switch(key_type) {
    case PUBKEY_DNS:
    case PUBKEY_DNSONDEMAND:
      starter_log(LOG_LEVEL_DEBUG, "conn %s/%s has key%u from DNS",
                  connection_name(conn), lr, keynum);
      if(ckaid_buf) {
        snprintf(ckaid_buf, ckaid_buf_len, "dnskey");
      }
      break;

    case PUBKEY_CERTIFICATE:
      starter_log(LOG_LEVEL_DEBUG, "conn %s/%s has key%u from certificate",
                  connection_name(conn), lr, keynum);
      if(ckaid_buf) {
        snprintf(ckaid_buf, ckaid_buf_len, "certificate");
      }
      break;

    case PUBKEY_NOTSET:
      break;

    case PUBKEY_PREEXCHANGED:
      err = atobytes((char *)rsakey, 0, (char *)keyspace, sizeof(keyspace),
                     &keylen);

      if(ckaid_buf) {
        calc_ckaid(ckaid_buf, ckaid_buf_len, keyspace, keylen);
      }
      //starter_log(LOG_LEVEL_ERR, "keyspace: %p len: %d", keyspace, keylen);
      //log_ckaid("loading key %s", keyspace, keylen);

      if (err) {
        starter_log(LOG_LEVEL_ERR, "conn %s/%s: rsakey%u malformed [%s]",
                    connection_name(conn), lr, keynum, err);
        return 1;
      }
      else {
        clonereplacechunk(msg->keyval, keyspace, keylen, "rsakey");
        return 0;
      }
    }
  }

  /* nothing to send, do not send it */
  return 2;
}

static int starter_whack_add_pubkey (struct starter_config *cfg,
				     struct starter_conn *conn,
				     struct starter_end *end, const char *lr)
{
	struct whack_message msg;
        char ckaid_print_buf[CKAID_PRINT_BUF_LEN];
	int ret;

	ret = 0;

	init_whack_msg(&msg);
        ret = starter_whack_build_pkmsg(cfg, &msg, conn, end
                                        , 1, end->rsakey1_type, end->rsakey1
                                        , ckaid_print_buf, sizeof(ckaid_print_buf), lr);
        starter_log(LOG_LEVEL_DEBUG, "   looking for key1, result=%d", ret);

        if(ret==0) {
          starter_log(LOG_LEVEL_DEBUG, "   sending pubkey 1: %s", ckaid_print_buf);
          end->rsakey1_ckaid = clone_str(ckaid_print_buf, "pubkey 1 ckaid");
          ret = send_whack_msg(cfg, &msg);
          if(ret != 0) return ret;
        }

	init_whack_msg(&msg);
        ret = starter_whack_build_pkmsg(cfg, &msg, conn, end
                                        , 2, end->rsakey2_type, end->rsakey2
                                        , ckaid_print_buf, sizeof(ckaid_print_buf), lr);
        starter_log(LOG_LEVEL_DEBUG, "   looking for key2, result=%d", ret);

        if(ret==0) {
          starter_log(LOG_LEVEL_DEBUG, "   sending pubkey 2: %s", ckaid_print_buf);
          end->rsakey2_ckaid = clone_str(ckaid_print_buf, "pubkey 2 ckaid");
          ret = send_whack_msg(cfg, &msg);
          if(ret != 0) return ret;
        }

        return 0;
}


int starter_whack_build_basic_conn(struct starter_config *cfg
                                   , struct whack_message *msg
                                   , struct starter_conn *conn)
{
	init_whack_msg(msg);

	msg->whack_connection = TRUE;
	msg->whack_delete = TRUE;      /* always do replace for now */
	msg->name = connection_name(conn);

        /* XXX maybe before here, we have already validated that left/right are
         *     in the same address family.
         */
	msg->end_addr_family = conn->end_addr_family;
        msg->tunnel_addr_family = conn->tunnel_addr_family;
        starter_log(LOG_LEVEL_DEBUG,
                    "emitting conn %s with end-family: %u and tunnel-family: %u\n",
                    conn->name,
                    msg->end_addr_family, msg->tunnel_addr_family);

	msg->sa_ike_life_seconds = conn->options[KBF_IKELIFETIME];
	msg->sa_ipsec_life_seconds = conn->options[KBF_SALIFETIME];
	msg->sa_rekey_margin = conn->options[KBF_REKEYMARGIN];
	msg->sa_rekey_fuzz = conn->options[KBF_REKEYFUZZ];
	msg->sa_keying_tries = conn->options[KBF_KEYINGTRIES];

	msg->policy = conn->policy;

	msg->connalias = conn->connalias;

	msg->metric = conn->options[KBF_METRIC];

	if(conn->options_set[KBF_CONNMTU]) {
		msg->connmtu   = conn->options[KBF_CONNMTU];
	}

	if(conn->options_set[KBF_DPDDELAY] &&
	   conn->options_set[KBF_DPDTIMEOUT]) {
		msg->dpd_delay   = conn->options[KBF_DPDDELAY];
		msg->dpd_timeout = conn->options[KBF_DPDTIMEOUT];

		if(conn->options_set[KBF_DPDACTION]) {
			msg->dpd_action = conn->options[KBF_DPDACTION];
		} else {
			/*
			 * there is a default DPD action, but DPD is only
			 * enabled if there is a dpd delay set.
			 */
			msg->dpd_action = DPD_ACTION_HOLD;
		}

	} else {
		if(conn->options_set[KBF_DPDDELAY]  ||
		   conn->options_set[KBF_DPDTIMEOUT]||
		   conn->options_set[KBF_DPDACTION])
		{
			starter_log(LOG_LEVEL_ERR, "conn: \"%s\" warning dpd settings are ignored unless both dpdtimeout= and dpddelay= are set"
				    , conn->name);
		}
	}
#ifdef NAT_TRAVERSAL
	if(conn->options_set[KBF_FORCEENCAP]) {
		msg->forceencaps=conn->options[KBF_FORCEENCAP];
	}
#endif

	msg->first_msgid = 0; // default firstmsgid to 0 if not provided
	if(conn->options_set[KBF_FIRSTMSGID])
		msg->first_msgid = conn->options[KBF_FIRSTMSGID];

	/*Cisco interop : remote peer type*/
	if(conn->options_set[KBF_REMOTEPEERTYPE]) {
		msg->remotepeertype=conn->options[KBF_REMOTEPEERTYPE];
	}

	if(conn->options_set[KBF_SHA2_TRUNCBUG]) {
		msg->sha2_truncbug=conn->options[KBF_SHA2_TRUNCBUG];
	}

#ifdef HAVE_NM
	/*Network Manager support*/
	if(conn->options_set[KBF_NMCONFIGURED]) {
		msg->nmconfigured=conn->options[KBF_NMCONFIGURED];
	}
#endif


#ifdef HAVE_LABELED_IPSEC
	/*Labeled ipsec support*/
	if(conn->options_set[KBF_LOOPBACK]) {
		msg->loopback=conn->options[KBF_LOOPBACK];
	}
	starter_log(LOG_LEVEL_INFO, "conn: \"%s\" loopback=%d", conn->name, msg->loopback);

        if(conn->options_set[KBF_LABELED_IPSEC]) {
                msg->labeled_ipsec=conn->options[KBF_LABELED_IPSEC];
        }
	starter_log(LOG_LEVEL_INFO, "conn: \"%s\" labeled_ipsec=%d", conn->name, msg->labeled_ipsec);

	msg->policy_label = conn->policy_label;
	starter_log(LOG_LEVEL_INFO, "conn: \"%s\" policy_label=%d", conn->name, msg->policy_label);
#endif

	if(set_whack_end(cfg, conn, "left",  &msg->left, &conn->left) != 0
           || set_whack_end(cfg, conn, "right", &msg->right, &conn->right)!=0) {
          return -1;
        }

	/* for bug #1004 */
	update_ports(msg);

	msg->esp = conn->esp;
	msg->ike = conn->ike;
	msg->tpmeval = NULL;

        return 0;
}

static int starter_whack_basic_add_conn(struct starter_config *cfg
					, struct starter_conn *conn)
{
	struct whack_message msg;
	int r = 0;

	init_whack_msg(&msg);

        /*
         * it seems smarter to load the keys required first, even though on error that might
         * leave keys loaded which might never get used.
         */
	if (conn->policy & POLICY_RSASIG) {
          starter_log(LOG_LEVEL_DEBUG, "conn: \"%s\" sending RSA keys for left", conn->name);
          r=starter_whack_add_pubkey (cfg, conn, &conn->left,  "left");
          if(r==0) {
            starter_log(LOG_LEVEL_DEBUG, "conn: \"%s\" sending RSA keys for right", conn->name);
            r=starter_whack_add_pubkey (cfg, conn, &conn->right, "right");
          }
	}
        if(r != 0) return r;

        r = starter_whack_build_basic_conn(cfg, &msg, conn);
        if(r != 0) return r;
	r =  send_whack_msg(cfg, &msg);

	return r;
}

bool one_subnet_from_string(struct starter_conn *conn
			    , char **psubnets
			    , int af
			    , ip_subnet *sn
			    , char *lr)
{
	char *eln;
	char *subnets = *psubnets;
	err_t e;

	if(subnets == NULL) {
		return FALSE;
	}

	/* find first non-space item */
	while(*subnets!='\0' && (isspace(*subnets) || *subnets==',')) subnets++;

	/* did we find something? */
	if(*subnets=='\0') return FALSE;  /* no */

	eln = subnets;

	/* find end of this item */
        while(*subnets!='\0' && !(isspace(*subnets) || *subnets==',')) subnets++;

	e = ttosubnet(eln, subnets-eln, af, sn);
	if(e) {
		starter_log(LOG_LEVEL_ERR, "conn: \"%s\" warning '%s' is not a subnet declaration. (%ssubnets)"
			    , conn->name
			    , eln, lr);
	}

	*psubnets = subnets;
	return TRUE;
}

/*
 * permutate_conns - generate all combinations of subnets={}
 *
 * @operation - the function to apply to each generated conn
 * @cfg       - the base configuration
 * @conn      - the conn to permute
 *
 * This function goes through the set of N x M combinations of the subnets
 * defined in conn's "subnets=" declarations and synthesizes conns with
 * the proper left/right subnet setttings, and then calls operation(),
 * (which is usually add/delete/route/etc.)
 *
 */
int starter_permutate_conns(int (*operation)(struct starter_config *cfg
					     , struct starter_conn *conn)
			    , struct starter_config *cfg
			    , struct starter_conn *conn)
{
	struct starter_conn sc;
	bool done = FALSE;
	int lc,rc;
	char *leftnets, *rightnets;
	char tmpconnname[256];
	ip_subnet lnet,rnet;

	leftnets = "";
	if(conn->left.strings_set[KSCF_SUBNETS]) {
		leftnets = conn->left.strings[KSCF_SUBNETS];
	}

	rightnets = "";
	if(conn->right.strings_set[KSCF_SUBNETS]) {
		rightnets =conn->right.strings[KSCF_SUBNETS];
	}

	/*
	 * the first combination is the current leftsubnet/rightsubnet
	 * value, and then each iteration of rightsubnets, and then
	 * each permutation of leftsubnets X rightsubnets.
	 *
	 * If both subnet= is set and subnets=, then it is as if an extra
	 * element of subnets= has been added, so subnets= for only one
	 * side will do the right thing, as will some combinations of also=
	 *
	 */

	if(conn->left.strings_set[KSCF_SUBNET]) {
		lnet = conn->left.subnet;
		lc=0;
	} else {
		one_subnet_from_string(conn, &leftnets, conn->tunnel_addr_family, &lnet, "left");
		lc=1;
	}

	if(conn->right.strings_set[KSCF_SUBNET]) {
		rnet = conn->right.subnet;
		rc=0;
	} else {
		one_subnet_from_string(conn, &rightnets, conn->tunnel_addr_family, &rnet, "right");
		rc=1;
	}

	do {
		int success;

		/* copy conn  --- we can borrow all pointers, since this
		 * is a temporary copy */
		sc = *conn;

		/* fix up leftsubnet/rightsubnet properly, make sure
		 * that has_client is set.
		 */
		sc.left.subnet = lnet;
		sc.left.has_client = TRUE;

		sc.right.subnet = rnet;
		sc.right.has_client = TRUE;

		snprintf(tmpconnname,256,"%s/%ux%u", conn->name, lc, rc);
		sc.name = tmpconnname;

		sc.connalias = conn->name;

		success = (*operation)(cfg, &sc);
		if(success != 0) {
			/* fail at first failure? . I think so */
			return success;
		}


		/* okay, advance right first, and if it is out, then do
		 * left.
		 */
		rc++;
		if(!one_subnet_from_string(conn, &rightnets, conn->tunnel_addr_family, &rnet, "right")) {
			/* reset right, and advance left! */
			rightnets = "";
			if(conn->right.strings_set[KSCF_SUBNETS]) {
				rightnets =conn->right.strings[KSCF_SUBNETS];
			}

			/* should rightsubnet= be the first item ? */
			if(conn->right.strings_set[KSCF_SUBNET]) {
				rnet = conn->right.subnet;
				rc=0;
			} else {
				one_subnet_from_string(conn, &rightnets, conn->tunnel_addr_family, &rnet, "right");
				rc = 1;
			}

			/* left */
			lc++;
			if(!one_subnet_from_string(conn, &leftnets, conn->tunnel_addr_family, &lnet, "left")) {
				done = 1;
			}
		}

	} while(!done);

	return 0;  /* success. */
}


int starter_whack_add_conn(struct starter_config *cfg
			   , struct starter_conn *conn)
{
	/* basic case, nothing special to synthize! */
	if(!conn->left.strings_set[KSCF_SUBNETS] &&
	   !conn->right.strings_set[KSCF_SUBNETS]) {
		return starter_whack_basic_add_conn(cfg,conn);
	}

	return starter_permutate_conns(starter_whack_basic_add_conn
				       , cfg, conn);
}

int starter_whack_basic_del_conn (struct starter_config *cfg
				  , struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_delete = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(cfg, &msg);
}

int starter_whack_del_conn(struct starter_config *cfg
			   , struct starter_conn *conn)
{
	/* basic case, nothing special to synthize! */
	if(!conn->left.strings_set[KSCF_SUBNETS] &&
	   !conn->right.strings_set[KSCF_SUBNETS]) {
		return starter_whack_basic_del_conn(cfg,conn);
	}

	return starter_permutate_conns(starter_whack_basic_del_conn
				       , cfg, conn);
}

int starter_whack_basic_route_conn (struct starter_config *cfg
				    , struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_route = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(cfg, &msg);
}

int starter_whack_route_conn(struct starter_config *cfg
			   , struct starter_conn *conn)
{
	/* basic case, nothing special to synthize! */
	if(!conn->left.strings_set[KSCF_SUBNETS] &&
	   !conn->right.strings_set[KSCF_SUBNETS]) {
		return starter_whack_basic_route_conn(cfg,conn);
	}

	return starter_permutate_conns(starter_whack_basic_route_conn
				       , cfg, conn);
}

int starter_whack_initiate_conn (struct starter_config *cfg
				 ,struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_initiate = TRUE;
	msg.whack_async = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(cfg, &msg);
}

int starter_whack_listen (struct starter_config *cfg)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_listen = TRUE;
	return send_whack_msg(cfg, &msg);
}

int starter_whack_shutdown (struct starter_config *cfg)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_shutdown = TRUE;
	return send_whack_msg(cfg, &msg);
}

void starter_whack_init_cfg(struct starter_config *cfg)
{
  cfg->send_whack_msg = send_whack_msg_to_socket;
}
