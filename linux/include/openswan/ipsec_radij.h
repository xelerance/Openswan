/*
 * @(#) Definitions relevant to the IPSEC <> radij tree interfacing
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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

#ifndef _IPSEC_RADIJ_H

#include <openswan.h>

int ipsec_walk(char *);

void ipsec_rj_walker_procprint(struct seq_file *m, struct radij_node *rn);
int ipsec_rj_walker_delete(struct radij_node *, void *);

enum walkonce_control_t {
  WALK_DONE = 0,
  WALK_DOTOP = 1,
  WALK_DODUPEKEY = 2,
  WALK_PROCNODE  = 3,
};

struct rj_walkstate {
  struct radij_node *rn;
  struct radij_node *base;
  struct radij_node *next;
  struct radij_node *current_node;
  enum walkonce_control_t walkonce_control;
  int (*f)(struct radij_node *,void *);
  void *w;
};
int rj_initwalk(struct rj_walkstate *rjws,
                struct radij_node_head *head,
                int (*func)(struct radij_node *,void *),
                void *extra);
int rj_walktreeonce(struct rj_walkstate *rjs);
void rj_walktreeonce_top(struct rj_walkstate *rjs);
extern void rj_finiwalk(struct rj_walkstate *rjws);

/* This structure is used to pass information between
 * ipsec_eroute_get_info and ipsec_rj_walker_procprint
 * (through rj_walktree) and between calls of ipsec_rj_walker_procprint.
 */
struct wsbuf
{
       /* from caller of ipsec_eroute_get_info: */
       char *const buffer;     /* start of buffer provided */
       const int length;       /* length of buffer provided */
       const off_t offset;     /* file position of first character of interest */
       /* accumulated by ipsec_rj_walker_procprint: */
       int len;        /* number of character filled into buffer */
       off_t begin;    /* file position contained in buffer[0] (<=offset) */
};

extern struct radij_node_head *rnh;
extern unsigned int rnh_count;
extern spinlock_t eroute_lock;

struct eroute * ipsec_findroute(struct sockaddr_encap *);

#define O1(x) (int)(((x)>>24)&0xff)
#define O2(x) (int)(((x)>>16)&0xff)
#define O3(x) (int)(((x)>>8)&0xff)
#define O4(x) (int)(((x))&0xff)

extern int debug_radij;
void rj_dumptrees(void);

#define DB_RJ_DUMPTREES	0x0001
#define DB_RJ_FINDROUTE 0x0002

#define _IPSEC_RADIJ_H
#endif

