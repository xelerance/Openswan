/* FreeS/WAN whack functions to communicate with pluto (whack.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: starterwhack.c,v 1.8 2004/12/01 07:33:14 ken Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <linux/stddef.h>
#include <unistd.h>
#include <errno.h>

#include "ipsecconf/starterwhack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"

#ifndef _OPENSWAN_H
#include <openswan.h>  /** FIXME: ugly include lines **/
#include "constants.h"
#endif

#include "oswalloc.h"
#include "whack.h"

static int send_whack_msg (struct whack_message *msg)
{
	struct sockaddr_un ctl_addr = { AF_UNIX, CTL_FILE };
	int sock;
	ssize_t len;
	struct whackpacker wp;
	err_t ugh;

	/**
	 * Pack strings
	 */
	wp.msg = msg;
	wp.str_next = (char *)msg->string;
	wp.str_roof = (char *)&msg->string[sizeof(msg->string)];

	ugh = pack_whack_msg(&wp);

	if(ugh)
	{
	    starter_log(LOG_LEVEL_ERR, "send_wack_msg(): can't pack strings: %s", ugh);
	    return -1;
	}

	len = wp.str_next - (unsigned char *)msg;

	/**
	 * Connect to pluto ctl
	 */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
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
	 * TODO: read reply
	 */

	close(sock);
	return 0;
}

static void init_whack_msg (struct whack_message *msg)
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
	return conn->name;
}

static void set_whack_end(struct whack_end *w, struct starter_end *l)
{
	w->id = l->id;
	w->host_addr = l->addr;
	w->host_nexthop = l->nexthop;
	w->has_client = l->has_client;
	if (l->has_client) {
		w->client = l->subnet;
	}
	else {
		w->client.addr.u.v4.sin_family = AF_INET;
	}
	w->updown = l->strings[KSCF_UPDOWN];
	w->host_port = IKE_UDP_PORT;
	w->has_client_wildcard = l->has_client_wildcard;
	w->cert = l->cert;
	w->protocol = l->protocol;
	w->port = l->port;
#ifdef VIRTUAL_IP
	w->virt = l->virt;
#endif
}

static int starter_whack_add_pubkey (struct starter_conn *conn,
	struct starter_end *end, const char *lr)
{
	const char *err;
	static char keyspace[1024 + 4];
	struct whack_message msg;

	init_whack_msg(&msg);

	msg.whack_key = TRUE;
	msg.pubkey_alg = PUBKEY_ALG_RSA;
	if (end->id && end->rsakey1) {
		msg.keyid = end->id;
		err = atobytes(end->rsakey1, 0, keyspace, sizeof(keyspace),
			&msg.keyval.len);
		if (err) {
			starter_log(LOG_LEVEL_ERR, "conn %s/%s: rsakey malformed [%s]",
				connection_name(conn), lr, err);
			return 1;
		}
		else {
			msg.keyval.ptr = keyspace;
			return send_whack_msg(&msg);
		}
	}
	if (end->id && end->rsakey2) {
		msg.keyid = end->id;
		err = atobytes(end->rsakey2, 0, keyspace, sizeof(keyspace),
			&msg.keyval.len);
		if (err) {
			starter_log(LOG_LEVEL_ERR, "conn %s/%s: rsakey malformed [%s]",
				connection_name(conn), lr, err);
			return 1;
		}
		else {
			msg.keyval.ptr = keyspace;
			return send_whack_msg(&msg);
		}
	}
	return 0;
}

int starter_whack_add_conn (struct starter_conn *conn)
{
	struct whack_message msg;
	int r;

	init_whack_msg(&msg);

	msg.whack_connection = TRUE;
	msg.name = connection_name(conn);

	msg.addr_family = AF_INET;
	msg.tunnel_addr_family = AF_INET;

	msg.sa_ike_life_seconds = conn->options[KBF_IKELIFETIME];
	msg.sa_ipsec_life_seconds = conn->options[KBF_SALIFETIME];
	msg.sa_rekey_margin = conn->options[KBF_REKEYMARGIN];
	msg.sa_rekey_fuzz = conn->options[KBF_REKEYFUZZ];
	msg.sa_keying_tries = conn->options[KBF_KEYINGTRIES];

	msg.policy = conn->policy;

	set_whack_end(&msg.left, &conn->left);
	set_whack_end(&msg.right, &conn->right);

	msg.esp = conn->esp;
	msg.ike = conn->ike;

	r =  send_whack_msg(&msg);

	if ((r==0) && (conn->policy & POLICY_RSASIG)) {
		r += starter_whack_add_pubkey (conn, &conn->left, "left");
		r += starter_whack_add_pubkey (conn, &conn->right, "right");
	}

	return r;
}

int starter_whack_del_conn (struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_delete = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg);
}

int starter_whack_route_conn (struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_route = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg);
}

int starter_whack_initiate_conn (struct starter_conn *conn)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_initiate = TRUE;
	msg.whack_async = TRUE;
	msg.name = connection_name(conn);
	return send_whack_msg(&msg);
}

int starter_whack_listen (void)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_listen = TRUE;
	return send_whack_msg(&msg);
}

int starter_whack_shutdown (void)
{
	struct whack_message msg;
	init_whack_msg(&msg);
	msg.whack_shutdown = TRUE;
	return send_whack_msg(&msg);
}

