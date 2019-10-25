/* FreeS/WAN whack functions to communicate with pluto (whack.h)
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
 */

#ifndef _STARTER_WHACK_H_
#define _STARTER_WHACK_H_

struct starter_conn;
struct starter_config;
struct starter_end;
struct whack_message;
enum pubkey_source;

int starter_whack_add_conn (struct starter_config *cfg, struct starter_conn *conn);
int starter_whack_del_conn (struct starter_config *cfg, struct starter_conn *conn);
int starter_whack_route_conn (struct starter_config *cfg, struct starter_conn *conn);
int starter_whack_initiate_conn (struct starter_config *cfg, struct starter_conn *conn);
int starter_whack_listen (struct starter_config *cfg);
int starter_whack_shutdown (struct starter_config *cfg);
void starter_whack_init_cfg(struct starter_config *cfg);
void init_whack_msg (struct whack_message *msg);

/* build whack message from starter structures */
extern int starter_whack_build_pkmsg(struct starter_config *cfg,
                                     struct whack_message *msg,
                                     struct starter_conn *conn,
                                     struct starter_end *end,
                                     unsigned int keynum,
                                     enum pubkey_source key_type,
                                     unsigned char *rsakey,
                                     char *ckaid_buf, size_t ckaid_buf_len,
                                     const char *lr);

/* serialize strings */
extern int serialize_whack_msg(struct whack_message *msg);

extern int starter_whack_build_basic_conn(struct starter_config *cfg
                                          , struct whack_message *msg
                                          , struct starter_conn *conn);

extern int starter_permutate_conns(int (*operation)(struct starter_config *cfg
						    , struct starter_conn *conn)
				   , struct starter_config *cfg
				   , struct starter_conn *conn);


#endif /* _STARTER_WHACK_H_ */

