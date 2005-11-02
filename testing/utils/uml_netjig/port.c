/*
 * @(#) jig to exercise a UML/FreeSWAN kernel with two interfaces
 *
 * Copyright (C) 2001 Jeff Dike Jeff Dike <jdike@karaya.com>
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
 * RCSID $Id: port.c,v 1.16 2003/04/07 02:43:22 mcr Exp $
 *
 * @(#) based upon uml_router from User-Mode-Linux tools package by Jeff Dike.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>

#include "pcap.h"
#include "hash.h"
#include "port.h"

#include "nethub.h"

struct port {
	TAILQ_ENTRY(port) link;
	int control;
	void *data;
	int data_len;
	packet_sender sender;
        unsigned char most_recent_ethernet[ETH_ALEN];
};

#define IS_BROADCAST(addr) ((addr[0] & 1) == 1)

static void free_port(struct netjig_state *ns,
		      struct nethub *nh,
		      struct port *port)
{
  TAILQ_REMOVE(&nh->nh_ports,port,link);
  free(port);
}

void close_port(struct netjig_state *ns,
		struct nethub *nh,
		int fd)
{
  struct port *port;

  for(port = nh->nh_ports.tqh_first;
      port != NULL;
      port = port->link.tqe_next){
    if(port->control == fd) break;
  }

  if(port == NULL){
    fprintf(stderr, "No port associated with descriptor %d\n", fd);
    return;
  }
  free_port(ns, nh, port);
}

static void update_src(struct netjig_state *ns,
		       struct nethub       *nh,
		       struct port *port,
		       struct packet *p)
{
  struct port *last;

  /* We don't like broadcast source addresses */
  if(IS_BROADCAST(p->header.src)) return;  

  last = find_in_hash(nh, p->header.src);

  if(port != last){
    /* old value differs from actual input port */

    if(ns->verbose) {
      fprintf(stderr,
	      " Addr: %02x:%02x:%02x:%02x:%02x:%02x "
	      " New port %d",
	      p->header.src[0], p->header.src[1], p->header.src[2],
	      p->header.src[3], p->header.src[4], p->header.src[5],
	      port->control);
    }

    if(last != NULL){
      if(ns->verbose) {
	fprintf(stderr, "old port %d", last->control);
      }
      delete_hash(nh, p->header.src);
    }
    if(ns->verbose) {
      fprintf(stderr, "\n");
    }

    memcpy(port->most_recent_ethernet, p->header.src, ETH_ALEN);
    insert_into_hash(nh, p->header.src, port);
  }
  update_entry_time(nh, p->header.src);
}

static void send_dst(struct netjig_state *ns,
		     struct nethub       *nh,
		     struct port *srcport,
		     struct packet *packet, int len, 
		     int hub)
{
  struct port *target, *p;

  target = find_in_hash(nh, packet->header.dest);
  if((target == NULL) || IS_BROADCAST(packet->header.dest) || hub){
    if((target == NULL) && !IS_BROADCAST(packet->header.dest)){
      if(ns->verbose) {
	fprintf(stderr,
		"hub %s unknown Addr: %02x:%02x:%02x:%02x:%02x:%02x from port %d\n",
		nh->nh_name,
		packet->header.src[0], packet->header.src[1], 
		packet->header.src[2], packet->header.src[3], 
		packet->header.src[4], packet->header.src[5],
		(srcport == NULL) ? -1 : srcport->control);
      }
    } 

    /* no cache or broadcast/multicast == all ports */
    for(p = nh->nh_ports.tqh_first;
	p != NULL;
	p = p->link.tqe_next){
      /* don't send it back the port it came in */
      if(p == srcport) continue;

      /* don't send to ports that aren't initalized yet */
      if(!p->sender) continue;

      (*p->sender)(p->control, packet, len, p->data);
    }
  }
  else (*target->sender)(target->control, packet, len, target->data);
}

void insert_data(struct netjig_state *ns,
		 struct nethub *nh,
		 struct packet *packet, int len)
{
  send_dst(ns, nh, NULL, packet, len, nh->nh_hub);
}


void handle_data(struct netjig_state *ns,
		 struct nethub *nh,
		 struct packet *packet, int len,
		 int   fd,
		 void *data, int (*matcher)(int port_fd, int data_fd, 
					    void *port_data,
					    int port_data_len, 
					    void *data))
{
  struct pcap_pkthdr ph;
  struct port *p;

  if(matcher) {
	  for(p = nh->nh_ports.tqh_first;
	      p != NULL;
	      p = p->link.tqe_next){
		  if((*matcher)(p->control, fd, p->data, p->data_len, data)) break;
	  }
  
	  /* if we have an incoming port (we will unless the packet is inserted) */
	  if(p != NULL) update_src(ns, nh, p, packet);
  }

  memset(&ph, 0, sizeof(ph));
  ph.caplen = len;
  ph.len    = len;

  if(nh->nh_outputFile) {
    pcap_dump((u_char *)nh->nh_output, &ph, (u_char *)packet);
  }

#ifdef NETDISSECT
  /* now dump it to tcpdump dissector if one was configured */
  if(tcpdump_print) {
    fprintf(stderr, "%8s:", nh->nh_name);
    ether_if_print((u_char *)&gndo, &ph, (u_char *)packet);
  }
#endif

#ifdef ARP_PROCESS
  if(nh->nh_defaultgate.s_addr!=0 || nh->nh_allarp) {
    if(packet->header.proto == htons(ETHERTYPE_ARP)) {
      struct arphdr *ahdr;
      
      ahdr = (struct arphdr *)&packet->data;
      if(ahdr->ar_hrd == htons(ARPHRD_ETHER) &&
	 ahdr->ar_pro == htons(ETHERTYPE_IP) &&
	 ahdr->ar_hln == ETH_ALEN &&
	 ahdr->ar_pln == 4 &&
	 ahdr->ar_op  == htons(ARPOP_REQUEST)) {
	u_int32_t *tip;
	u_int32_t *sip;
	sip = (u_int32_t *)(packet->data + /*sizeof(arphdr)*/8 + 1*ETH_ALEN);
	tip = (u_int32_t *)(packet->data + /*sizeof(arphdr)*/8 + 2*ETH_ALEN + 4);

	if(nh->nh_allarp == 1 || *tip == nh->nh_defaultgate.s_addr) {
	  /* AHA! reply to ARP request */
	  
	  /* we mutate this packet in place */
	  /* change this to a reply */
	  ahdr->ar_op = htons(ARPOP_REPLY);

	  /* swap ether fields */
	  memcpy(packet->header.dest, packet->header.src, ETH_ALEN);

	  memcpy(packet->data + 8, nh->nh_defaultether, ETH_ALEN);
	  memcpy(packet->header.src, nh->nh_defaultether, ETH_ALEN);

	  /* swap ip fields */
	  {
	    uint32_t tmp;
	    tmp=*sip;
	    *sip=*tip;
	    *tip=tmp;
	  }

	  if(ns->verbose) {
	    fprintf(stderr, "%s: found ARP request, replying: \n",
		    nh->nh_name);
	  }
#ifdef NETDISSECT
	  if(tcpdump_print) {
	    struct pcap_pkthdr ph;

	    memset(&ph, 0, sizeof(ph));
	    
	    ph.caplen = len;
	    ph.len    = len;

	    fprintf(stderr, "%8s:", nh->nh_name);
	    ether_if_print((u_char *)&gndo, &ph, (u_char *)&packet);
	  }
#endif
	}
      }
    }
  }
#endif
  send_dst(ns, nh, p, packet, len, nh->nh_hub);  
}

static int match_tap(int port_fd, int data_fd, void *port_data, 
		     int port_data_len, void *data)
{
  return(port_fd == data_fd);
}

void handle_tap_data(struct netjig_state *ns,
		     struct nethub       *nh)
{
  struct packet packet;
  int len;

  len = read(nh->tap_fd, &packet, sizeof(packet));
  if(len < 0){
    if(errno != EAGAIN) perror("Reading tap data");
    return;
  }
  handle_data(ns, nh, &packet, len, nh->tap_fd, NULL, match_tap);
}

struct port *alloc_port(struct netjig_state *ns,
			struct nethub       *nh)
{
  struct port *port;

  port = malloc(sizeof(struct port));
  if(port == NULL){
    perror("malloc");
    return(NULL);
  }
  memset(port, 0, sizeof(struct port));

  TAILQ_INSERT_TAIL(&nh->nh_ports, port, link);
  return port;
}

struct sock_data {
  int fd;
  struct sockaddr_un sock;
};

static void send_sock(int fd, void *packet, int len, void *data)
{
  struct sock_data *mine = data;
  int err;
  
  err = sendto(mine->fd, packet, len, 0, (struct sockaddr *) &mine->sock,
	       sizeof(mine->sock));
  if(err != len) perror("send_sock");
}

static int match_sock(int port_fd, int data_fd, void *port_data, 
		      int port_data_len, void *data)
{
  struct sock_data *mine = data;
  struct sock_data *port = port_data;

  if(port_data_len != sizeof(*mine)) return(0);
  return(!memcmp(&port->sock, &mine->sock, sizeof(mine->sock)));
}


void handle_sock_data(struct netjig_state *ns,
		      struct nethub *nh)
{
  struct packet packet;
  struct sock_data data;
  int len, socklen = sizeof(data.sock);

  len = recvfrom(nh->data_fd,
		 &packet, sizeof(packet), 0, 
		 (struct sockaddr *) &data.sock, &socklen);

  if(len < 0){
    if(errno != EAGAIN) perror("handle_sock_data");
    return;
  }

  data.fd = nh->data_fd;
  handle_data(ns, nh, &packet, len, nh->data_fd, &data, match_sock);
}


int setup_sock_port(struct netjig_state *ns,
		    struct nethub       *nh,
		    struct port         *port,
		    struct sockaddr_un  *name)
{
  struct sock_data *data;

  data = malloc(sizeof(*data));
  if(data == NULL){
    perror("setup_sock_port");
    return(-1);
  }
  data->fd   = nh->data_fd;
  data->sock = *name;
  
  port->sender = send_sock;
  port->data   = data;
  port->data_len=sizeof(*data);


  return(0);
}

int setup_sock_tap(struct netjig_state *ns,
		   struct nethub       *nh,
		   int    fd,
		   packet_sender        tap_sender)
{
  struct sock_data *data;
  struct port *np;

  np = alloc_port(ns, nh);

  data = malloc(sizeof(*data));
  if(data == NULL){
    perror("setup_sock_port");
    return(-1);
  }
  data->fd   = nh->data_fd;
  
  np->sender = tap_sender;
  np->data   = data;
  np->data_len=sizeof(*data);

  if(ns->verbose) {
    fprintf(stderr, "New tap connection\n");
  }
  return(0);
}

void new_port_v0(struct netjig_state *ns,
		 struct nethub *nh,
		 struct port *p,
		 struct request_v0 *req)
{
  switch(req->type){
  case REQ_NEW_CONTROL:
	  setup_sock_port(ns, nh, p, &req->u.new_control.name);
	  break;
    
  default:
	  fprintf(stderr, "Bad request type : %d\n", req->type);
	  close_descriptor(ns, nh, nh->data_fd);
  }
}

void new_port_v1_v3(struct netjig_state *ns,
		    struct nethub *nh,
		    struct port   *port,
		    enum request_type type, 
		    struct sockaddr_un *sock)
{
  int n, err;

  switch(type){
  case REQ_NEW_CONTROL:
    err = setup_sock_port(ns, nh, port, sock);
    if(err) return;
    n = write(port->control, &nh->data_sun, sizeof(nh->data_sun));
    if(n != sizeof(nh->data_sun)){
      fprintf(stderr, "Sending data socket name: %s\n", strerror(errno));
      close_descriptor(ns, nh, port->control);
    }
    break;
  default:
    fprintf(stderr, "Bad request type : %d\n", type);
    close_descriptor(ns, nh, port->control);
  }
}

void new_port_v2(struct netjig_state *ns,
		 struct nethub       *nh,
		 struct port         *p,
		 struct request_v2 *req)
{
  fprintf(stderr, "Version 2 is not supported\n");
  close_descriptor(ns, nh, p->control);
}

/*
 * called when data is ready on a new port
 */
void handle_new_port(struct netjig_state *ns,
		     struct nethub *nh,
		     struct port   *p) 
{
  union request req;
  int len;

  len = read(p->control, &req, sizeof(req));
  if(len < 0){
    if(errno != EAGAIN){
      perror("Reading request");
      close_descriptor(ns,nh,p->control);
    }
    return;
  }
  else if(len == 0){
    fprintf(stderr, "EOF from new port\n");
    close_descriptor(ns,nh,p->control);
    return;
  }

  if(req.v1.magic == SWITCH_MAGIC) {
          if(ns->verbose) {
	    fprintf(stderr,
		    "switch %s: new connection using daemon v.%d on port %d\n",
		    nh->nh_name, req.v2.version, p->control);
	  }
	  switch(req.v2.version) {
	  case 2:
		  new_port_v2(ns, nh, p, &req.v2);
		  break;
		  
	  case 3:
		  new_port_v1_v3(ns, nh, p, req.v3.type, &req.v3.sock);
		  break;
		  
	  case 1:
		  new_port_v1_v3(ns, nh, p, req.v1.type, &req.v1.u.new_control.name);
		  break;
		  
	  default:
		  fprintf(stderr, "Request for a version %d port, which this "
			  "uml_switch doesn't support\n", req.v2.version);
		  break;
	  }
  } else {
	  new_port_v0(ns, nh, p, &req.v0);
  }
}

static void service_port(struct netjig_state *ns,
			 struct nethub *nh,
			 struct port *port)
{
  int n;
  char c;

  if(ns->debug > 2) {
    fprintf(stderr, "servicing port %d\n", port->control);
  }

  n = read(port->control, &c, sizeof(c));
  if(n < 0) {
    fprintf(stderr, "while serving port %d of switch %s reading request: %s",
	    port->control, nh->nh_name, strerror(errno));
  }
  else if(n == 0) {
    if(ns->verbose) {
      fprintf(stderr, "Disconnect on switch (%s) from %d addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	      nh->nh_name,
	      port->control,
	      port->most_recent_ethernet[0], port->most_recent_ethernet[1],
	      port->most_recent_ethernet[2], port->most_recent_ethernet[3],
	      port->most_recent_ethernet[4], port->most_recent_ethernet[5]);
    }

    remove_fd(ns, port->control);
    free_port(ns, nh, port);
  }
  else {
    if(ns->verbose) {
      fprintf(stderr,
	      "Bad request on switch (%s) from %d addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	      nh->nh_name,
	      port->control,
	      port->most_recent_ethernet[0], port->most_recent_ethernet[1],
	      port->most_recent_ethernet[2], port->most_recent_ethernet[3],
	      port->most_recent_ethernet[4], port->most_recent_ethernet[5]);
    }
  }
}

void accept_connection(struct netjig_state *ns,
		       struct nethub       *nh)
{
  struct sockaddr addr;
  struct port *new_port;
  int len, new;

  len = sizeof(addr);
  new = accept(nh->ctl_listen_fd, &addr, &len);
  if(new < 0){
    perror("accept");
    return;
  }

#if 0
  if(fcntl(new, F_SETFL, O_NONBLOCK) < 0){
    perror("fcntl - setting O_NONBLOCK");
    close(new);
    return;
  }
#endif
  
  new_port = alloc_port(ns, nh);
  new_port->control = new;
  add_fd(ns, new);
}

void handle_port(struct netjig_state *ns,
		 struct nethub       *nh,
		 struct pollfd  *l_fds,
		 int             l_nfds,
		 int            *l_fd_array,
		 int             l_fd_array_size)
{
  struct port *p;
  struct port *next_port;
  
  for(p = nh->nh_ports.tqh_first;
      p != NULL;
      p = next_port)
    {
      next_port = p->link.tqe_next;

      if(p->control < l_fd_array_size &&
	 l_fd_array[p->control]!=-1) {

	if(l_fds[l_fd_array[p->control]].revents & POLLIN) {
	  if(p->sender) {
	    service_port(ns, nh, p);
	  } else {
	    handle_new_port(ns, nh, p);
	  }
	} else if(l_fds[l_fd_array[p->control]].revents & (POLLHUP|POLLERR)) {
	  remove_fd(ns, p->control);
	  free_port(ns, nh, p);
	}
      }
    }
}  
