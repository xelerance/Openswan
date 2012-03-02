/*
 * @(#) jig to exercise a UML/FreeSWAN kernel with two interfaces
 *
 * Copyright (C) 2001 Michael Richardson  <mcr@freeswan.org>
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
 * @(#) based upon uml_router from User-Mode-Linux tools package
 *
 */

extern char *progname;
extern jmp_buf getMeOut;

#define ETH_ALEN 6

#define MAX(x,y) ((x) > (y) ? (x) : (y))

/* prototypes */
extern void sig_handler(int sig);
extern void create_socket_dir(struct netjig_state *ns);
extern void cmdprompt(struct netjig_state *ns);
extern void forward_data(struct nethub *nh, struct packet *p, int    len);
extern int cmdread(struct netjig_state *ns, char  *buf, int    len);
extern void *xmalloc1(size_t size, char *file, int linenum);

/* from cmdmode.c */

extern void finish_waitplay(struct netjig_state *ns);
extern int cmdread(struct netjig_state *ns, char  *buf, int    len);

/*
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 8
 * End:
 *
 */
