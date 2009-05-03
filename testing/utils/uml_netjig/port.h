/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#ifndef __PORT_H__
#define __PORT_H__

#include <sys/socket.h>
#include <sys/un.h>

struct netjig_state;
struct nethub;
struct port;
struct packet;

typedef void (*packet_sender)(int fd, void *packet, int len, void *data);

/* in port.c */
extern void handle_sock_data(struct netjig_state *ns,
			     struct nethub *nh);
extern void handle_tap_data(struct netjig_state *ns,
			    struct nethub  *nh);

extern void handle_port(struct netjig_state *ns,
			struct nethub       *nh,
			struct pollfd  *l_fds,
			int             l_nfds,
			int            *l_fd_array,
			int             l_fd_array_size);

extern void handle_data(struct netjig_state *ns,
			struct nethub *nh,
			struct packet *packet, int len,
			int   fd,
			void *data, int (*matcher)(int port_fd, int data_fd, 
						   void *port_data,
						   int port_data_len, 
						   void *data));

void insert_data(struct netjig_state *ns,
		 struct nethub *nh,
		 struct packet *packet, int len);


extern void close_port(struct netjig_state *ns,
		       struct nethub       *nh,
		       int fd);
extern int setup_sock_port(struct netjig_state *ns,
			   struct nethub       *nh,
			   struct port        *port,
			   struct sockaddr_un *name);

extern void setup_port(struct netjig_state *ns,
		       struct nethub       *nh,
		       struct port         *port,
		       int fd,
		       void (*sender)(int fd, void *packet, int len, 
				      void *data),
		       void *data, int data_len);

extern struct port *alloc_port(struct netjig_state *ns,
			       struct nethub       *nh);


extern int setup_sock_tap(struct netjig_state *ns,
			  struct nethub       *nh,
			  int    fd,
			  packet_sender        tap_sender);

extern void accept_connection(struct netjig_state *ns, struct nethub *nh);

#endif
