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

#ifndef _NETHUB_H_

#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include "pcap.h"

enum request_type { REQ_NEW_CONTROL };

struct request_v0 {
  enum request_type type;
  union {
    struct {
      unsigned char addr[ETH_ALEN];
      struct sockaddr_un name;
    } new_control;
  } u;
};

#define SWITCH_MAGIC 0xfeedface

struct request_v1 {
  unsigned long magic;
  enum request_type type;
  union {
    struct {
      unsigned char addr[ETH_ALEN];
      struct sockaddr_un name;
    } new_control;
  } u;
};

struct request_v2 {
  unsigned long magic;
  int version;
  enum request_type type;
  struct sockaddr_un sock;
};

struct reply_v2 {
  unsigned char mac[ETH_ALEN];
  struct sockaddr_un sock;
};

struct request_v3 {
  unsigned long magic;
  int version;
  enum request_type type;
  struct sockaddr_un sock;
};

union request {
  struct request_v0 v0;
  struct request_v1 v1;
  struct request_v2 v2;
  struct request_v3 v3;
};

#define HASH_SIZE 128
#define HASH_MOD 11

struct port;

struct nethub {
	TAILQ_ENTRY(nethub)     nh_link;
	TAILQ_HEAD(,port)  nh_ports;
	char              *nh_name;
	unsigned char      nh_defaultether[ETH_ALEN];
	struct in_addr     nh_defaultgate;
	int                nh_allarp;
	char              *nh_outputFile;
	pcap_dumper_t     *nh_output;
	int                nh_rate;
	char              *nh_inputFile;
	pcap_t            *nh_input;
	int                nh_hub;
	int                nh_compat_v0;
	char              *socket_dir;
	char              *pid_file_name;
	char              *ctl_socket_name_env;   /* do not free this one */
	char              *ctl_socket_name;
	int                ctl_listen_fd;
	char              *data_socket_name_env;  /* do not free this one */
	char              *data_socket_name;
	struct sockaddr_un data_sun;
	int                data_fd;
	int                tap_fd;
	struct hash_entry *h[HASH_SIZE];

};

#define CMDBUF_LEN 256
struct netjig_state {
	int   done;
	int   debug;
	int   verbose;
        int   waitplay;
	char *socketbasedir;
	char *startup;
	char *playprivatefile;
	char *recordprivatefile;
	char *playpublicfile;
	char *recordpublicfile;
	int arpreply;
	int cmdproto;
	int forcetick;   /* if set to 1, then a packet will be sent out */
	int packetrate;  /* how many miliseconds between packets */
	FILE *cmdproto_out;
	int exitonempty;
	TAILQ_HEAD(,nethub) switches;

	/* stuff to keep track of the sources of input */
	struct pollfd *fds;        /* array of input sources */
	int            nfds;       /* number of relevant entries */
	int            max_fds;    /* current size of the array */

	/* poll(2) doesn't provide a very useful interface to figure out what
	 * fd belongs to what event, and searching through stuff sucks, we
	 * we keep a mapping of fd# -> poll descriptor entry. We then walk through
	 * the set of possible inputs, (in the appropriate priority order) and
	 * use this array to map to an entry in fds[] to see if this input has
	 * activity.
	 */
	int            *fd_array;
	int             fd_array_size;  /* so we can grow it in add_fd() */


	/* keep track of curtent input buffer, since we predict that eventuallyu
	 * command sizes will grow such that they do not always fit into a single
	 * read(2), or that multiple commands may get coalesced into a single buffer.
	 */
	char cmdbuf[CMDBUF_LEN];
	int  cmdloc;
	int  cmdskip;
	int  cmdlaststat;         /* 0= success */
};

struct packet {
  struct {
    unsigned char dest[6];
    unsigned char src[6];
    u_int16_t     proto;
  } header;
  unsigned char data[1500];
};

/* in nethub.c */
extern struct nethub *init_nethub(struct netjig_state *ns,
				  char *switchname,
				  char *data_socket, char *ctl_socket,
				  int compat_v0);
extern void bind_sockets(struct nethub *nh);
extern void cleanup_nh(struct nethub *nh);
extern struct nethub *find_nethubbyname(struct netjig_state *ns, char *name);
extern void add_fd(struct netjig_state *ns, int fd);
extern void remove_fd(struct netjig_state *ns, int fd);

extern void close_descriptor(struct netjig_state *ns,
			     struct nethub       *nh,
			     int fd);

#define xmalloc(X) xmalloc1((X), __FILE__, __LINE__)

#ifdef NETDISSECT
#include "netdissect.h"
extern struct netdissect_options gndo;
#endif

extern void hexdump_block(const u_char *cp, u_int length);
extern int tcpdump_print;

#define _NETHUB_H_

#endif /* _NETHUB_H_ */

/*
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 8
 * End:
 *
 */

