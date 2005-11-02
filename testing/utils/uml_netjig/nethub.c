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
 * RCSID $Id: nethub.c,v 1.10 2002/08/30 01:37:35 mcr Exp $
 *
 * @(#) based upon uml_router from User-Mode-Linux tools package by Jeff Dike.
 *
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#define _GNU_SOURCE 1
#include <getopt.h>

#include "pcap.h"
#include <sys/queue.h>

#include "port.h"
#include "hash.h"

#ifdef NETDISSECT
#include "netdissect.h"

struct netdissect_options gndo;
int tcpdump_print = 1;
#endif

#include "nethub.h"
#include "netjig.h"

void cleanup_nh(struct nethub *nh)
{
  if(nh->pid_file_name) {
    if(unlink(nh->pid_file_name) < 0 && errno!=ENOENT) {
      fprintf(stderr, "Could not remove pid file '%s' : %s\n",
	      nh->ctl_socket_name, strerror(errno));
    }
    free(nh->pid_file_name);
    nh->pid_file_name = NULL;
  }

  if(nh->ctl_socket_name) {
    if(unlink(nh->ctl_socket_name) < 0){
      fprintf(stderr, "Couldn't remove control socket '%s' : %s\n",
	      nh->ctl_socket_name, strerror(errno));
    }
    free(nh->ctl_socket_name);
    nh->ctl_socket_name=NULL;
  }
  if(nh->ctl_listen_fd > 0) {
    close(nh->ctl_listen_fd);
    nh->ctl_listen_fd = -1;
  }

  if(nh->data_socket_name) {
    if(nh->data_socket_name!=NULL && unlink(nh->data_socket_name) < 0){
      fprintf(stderr, "Couldn't remove data socket '%s' : %s\n",
	      nh->data_socket_name, strerror(errno));
    }
    free(nh->data_socket_name);
    nh->data_socket_name=NULL;
  }

  if(nh->data_fd > 0) {
    close(nh->data_fd);
    nh->data_fd = -1;
  }
    
  if(nh->socket_dir != NULL && rmdir(nh->socket_dir) < 0) {
    fprintf(stderr, "Couldn't remove socket dir '%s' : %s\n",
	    nh->socket_dir, strerror(errno));
  }

  if(nh->nh_output) {
    pcap_dump_close(nh->nh_output);
    nh->nh_output=NULL;
  }
  if(nh->nh_outputFile) {
    free(nh->nh_outputFile);
    nh->nh_outputFile = NULL;
  }

  if(nh->nh_input) {
    pcap_close(nh->nh_input);
    nh->nh_input=NULL;
  }

  if(nh->nh_inputFile) {
    free(nh->nh_inputFile);
    nh->nh_inputFile = NULL;
  }

  /* XXX should free up hash entries and ports */
  free(nh);
}

void add_fd(struct netjig_state *ns,
	    int fd)
{
  struct pollfd *p;
  int i;

  /*  fprintf(stderr, "Adding fd %d\n", fd); */

  if(ns->nfds == ns->max_fds){
    ns->max_fds = ns->max_fds ? 2 * ns->max_fds : 4;
    if((ns->fds = realloc(ns->fds, ns->max_fds * sizeof(struct pollfd))) == NULL){
      perror("realloc");
      /* XXX need a better cleanup function ! */
      exit(1);
    }
  }
  p = &ns->fds[ns->nfds++];
  p->fd = fd;
  p->events = POLLIN;
  p->revents=0;

  /*
   * assuming that FD's are small integers is very Unix.
   * If you port this to WinBLOWs, well, sorry, figure out someone else.
   */
  while(fd >= ns->fd_array_size) {
    ns->fd_array_size = ns->fd_array_size ? 2*ns->fd_array_size : 4;
    if((ns->fd_array = realloc(ns->fd_array,
			       ns->fd_array_size * sizeof(int))) ==NULL) {
      perror("realloc fd_array");
      /* XXX need a better cleanup function ! */
      exit(1);
    }
  }

  /* we rebuild the fd->pollfd mapping here because we might have reallocated
   * it above, and recalculating it is pretty easy.
   */
  for(i=0; i < ns->fd_array_size; i++) {
    ns->fd_array[i]=-1;
  }

  for(i=0, p=ns->fds; i < ns->nfds; i++, p++) {
    /* fprintf(stderr, "Mapping fd:%d to item %d\n", p->fd, i); */

    ns->fd_array[p->fd]=i;
  }
}

void remove_fd(struct netjig_state *ns,
		      int fd)
{
  int i;

  for(i = 0; i < ns->nfds; i++){
    if(ns->fds[i].fd == fd) break;
  }
  if(i == ns->nfds){
    fprintf(stderr, "remove_fd : Couldn't find descriptor %d\n", fd);
  }
  memmove(&ns->fds[i], &ns->fds[i + 1], (ns->max_fds - i - 1) * sizeof(struct pollfd));
  ns->nfds--;

  if(fd < ns->fd_array_size) {
    ns->fd_array[fd]=-1;
  }
}

void close_descriptor(struct netjig_state *ns,
		      struct nethub       *nh,
		      int fd)
{
  remove_fd(ns, fd);
  close(fd);
  close_port(ns, nh, fd);
}

int still_used(struct sockaddr_un *sun)
{
  int test_fd, ret = 1;

  if((test_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }

  if(connect(test_fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
    if(errno == ECONNREFUSED){
      if(unlink(sun->sun_path) < 0){
	fprintf(stderr, "Failed to removed unused socket '%s': ", 
		sun->sun_path);
	perror("");
      }
      ret = 0;
    }
    else perror("connect");
  }
  close(test_fd);
  return(ret);
}


int bind_socket(int fd, const char *name, struct sockaddr_un *sock_out)
{
  struct sockaddr_un sun;

  memset(&sun, 0, sizeof(sun));

  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, name);
  
  if(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
    if((errno == EADDRINUSE) && still_used(&sun)) return(EADDRINUSE);
    else if(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0){
      perror("bind");
      return(EPERM);
    }
  }
  if(sock_out != NULL) *sock_out = sun;
  return(0);
}


void bind_sockets_v0(struct nethub *nh)
{
  int ctl_err, ctl_present = 0, ctl_used = 0;
  int data_err, data_present = 0, data_used = 0;
  int try_remove_ctl, try_remove_data;

  ctl_err = bind_socket(nh->ctl_listen_fd, nh->ctl_socket_name, NULL);
  if(ctl_err != 0) ctl_present = 1;
  if(ctl_err == EADDRINUSE) ctl_used = 1;

  data_err = bind_socket(nh->data_fd, nh->data_socket_name, &nh->data_sun);
  if(data_err != 0) data_present = 1;
  if(data_err == EADDRINUSE) data_used = 1;

  if(!ctl_err && !data_err) return;

  unlink(nh->ctl_socket_name);
  unlink(nh->data_socket_name);

  try_remove_ctl = ctl_present;
  try_remove_data = data_present;
  if(ctl_present && ctl_used){
    fprintf(stderr, "The control socket '%s' has another server "
	    "attached to it\n", nh->ctl_socket_name);
    try_remove_ctl = 0;
  }
  else if(ctl_present && !ctl_used)
    fprintf(stderr, "The control socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", nh->ctl_socket_name);
  if(data_present && data_used){
    fprintf(stderr, "The data socket '%s' has another server "
	    "attached to it\n", nh->data_socket_name);
    try_remove_data = 0;
  }
  else if(data_present && !data_used)
    fprintf(stderr, "The data socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", nh->data_socket_name);
  if(try_remove_ctl || try_remove_data){
    fprintf(stderr, "You can either\n");
    if(try_remove_ctl && !try_remove_data) 
      fprintf(stderr, "\tremove '%s'\n", nh->ctl_socket_name);
    else if(!try_remove_ctl && try_remove_data) 
      fprintf(stderr, "\tremove '%s'\n", nh->data_socket_name);
    else fprintf(stderr, "\tremove '%s' and '%s'\n",
		 nh->ctl_socket_name, nh->data_socket_name);
    fprintf(stderr, "\tor rerun with different, unused filenames for "
	    "sockets:\n");
    fprintf(stderr, "\t\t%s -unix <control> <data>\n", progname);
    fprintf(stderr, "\t\tand run the UMLs with "
	    "'eth0=daemon,,unix,<control>,<data>\n");
    exit(1);
  }
  else {
    fprintf(stderr, "You should rerun with different, unused filenames for "
	    "sockets:\n");
    fprintf(stderr, "\t%s -unix <control> <data>\n", progname);
    fprintf(stderr, "\tand run the UMLs with "
	    "'eth0=daemon,,unix,<control>,<data>'\n");
    exit(1);
  }
}

void bind_data_socket(int fd, struct sockaddr_un *sun)
{
  struct {
    char zero;
    int pid;
    int usecs;
  } name;
  struct timeval tv;

  name.zero = 0;
  name.pid = getpid();
  gettimeofday(&tv, NULL);
  name.usecs = tv.tv_usec;
  sun->sun_family = AF_UNIX;
  memcpy(sun->sun_path, &name, sizeof(name));
  if(bind(fd, (struct sockaddr *) sun, sizeof(*sun)) < 0){
    perror("Binding to data socket");
    exit(1);
  }
}

void bind_sockets(struct nethub *nh)
{
  int err, used;

  err = bind_socket(nh->ctl_listen_fd, nh->ctl_socket_name, NULL);
  if(err == 0){
    bind_data_socket(nh->data_fd, &nh->data_sun);
    return;
  }
  else if(err == EADDRINUSE) used = 1;
  
  if(used){
    fprintf(stderr, "The control socket '%s' has another server "
	    "attached to it\n", nh->ctl_socket_name);
    fprintf(stderr, "You can either\n");
    fprintf(stderr, "\tremove '%s'\n", nh->ctl_socket_name);
    fprintf(stderr, "\tor rerun with a different, unused filename for a "
	    "socket\n");
  }
  else
    fprintf(stderr, "The control socket '%s' exists, isn't used, but couldn't "
	    "be removed\n", nh->ctl_socket_name);
  exit(1);
}


#ifdef NETDISSECT
/* Like default_print() but data need not be aligned */
void
default_print_unaligned(struct netdissect_options *ipdo,
			register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	if (ipdo->ndo_Xflag) {
		ascii_print(ipdo, cp, length);
		return;
	}
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)fprintf(stderr, "\n\t\t\t");
		s = *cp++;
		(void)fprintf(stderr, " %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)fprintf(stderr, "\n\t\t\t");
		(void)fprintf(stderr, " %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(struct netdissect_options *ndo,
	      register const u_char *bp, register u_int length)
{
	default_print_unaligned(ndo, bp, length);
}
#endif

struct nethub *init_nethub(struct netjig_state *ns,
			   char *switchname,
			   char *data_socket,
			   char *ctl_socket,
			   int compat_v0)
{
	int one;
	char *env;
	char *newdir, *p;
	struct nethub *nh;
	int used_base_dir;

	one = 1;
	used_base_dir = 0;

	nh=xmalloc(sizeof(*nh));
	memset(nh, 0, sizeof(*nh));

	TAILQ_INIT(&nh->nh_ports);

	nh->nh_name = strdup(switchname);

	/* setup ARP stuff */
	nh->nh_allarp = 0;
	
	nh->nh_defaultgate.s_addr = 0;
	
	nh->nh_defaultether[0]=0x10;
	nh->nh_defaultether[1]=0x00;
	nh->nh_defaultether[2]=0x00;
	nh->nh_defaultether[3]=switchname[0];
	nh->nh_defaultether[4]=switchname[1];
	nh->nh_defaultether[5]=switchname[2];

	if(ctl_socket == NULL) {
	  /* cons up the names, and stick them in the environment */
	  env = xmalloc(sizeof("UML_")+2*strlen(switchname)+sizeof("CTL=")+
			strlen(ns->socketbasedir)+sizeof("/ctl")+4);
	  
	  sprintf(env, "UML_%s_CTL=%s/%s/ctl", switchname,
		  ns->socketbasedir, switchname);
	  putenv(env);
	  nh->ctl_socket_name_env = env;
	  nh->ctl_socket_name = strdup(strchr(env, '=')+1);
	  used_base_dir = 1;
	} else {
	  nh->ctl_socket_name_env = NULL;
	  nh->ctl_socket_name = strdup(ctl_socket);
	}

	if(data_socket == NULL) {
	  env = xmalloc(sizeof("UML_")+2*strlen(switchname)+sizeof("DATA=")+
			strlen(ns->socketbasedir)+sizeof("/data")+4);
	  
	  sprintf(env, "UML_%s_DATA=%s/%s/data", switchname,
		  ns->socketbasedir, switchname);
	  putenv(env);
	  nh->data_socket_name_env = env;
	  nh->data_socket_name = strdup(strchr(env, '=')+1);
	  used_base_dir = 1;
	} else {
	  nh->data_socket_name_env = NULL;
	  nh->data_socket_name = strdup(data_socket);
	}
	  

	/* now make the directory, if we need it */
 	if(used_base_dir ) {
		FILE *pidfile;

		if(mkdir(ns->socketbasedir,0700) < 0 &&
		   errno != EEXIST) {
			perror(ns->socketbasedir);
			exit(1);
		}

		newdir=strdup(nh->ctl_socket_name);
		if((p=strrchr(newdir, '/'))!=NULL) {
			*p='\0';
			if(mkdir(newdir, 0700) < 0 &&
			   errno != EEXIST) {
				perror(newdir);
				exit(1);
			}
		}
		nh->socket_dir=newdir;

		nh->pid_file_name=xmalloc(strlen(nh->socket_dir)+sizeof("pid")+2);
		sprintf(nh->pid_file_name, "%s/pid", nh->socket_dir);
		if((pidfile=fopen(nh->pid_file_name, "w"))==NULL) {
			perror(nh->pid_file_name);
		} else {
			fprintf(pidfile, "%d", getpid());
			fclose(pidfile);
		}
	} 

	if((nh->ctl_listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
		perror("socket");
		exit(1);
	}
	if(setsockopt(nh->ctl_listen_fd,
		      SOL_SOCKET, SO_REUSEADDR, (char *) &one, 
		      sizeof(one)) < 0){
		perror("setsockopt");
		exit(1);
	}

	if(fcntl(nh->ctl_listen_fd, F_SETFL, O_NONBLOCK) < 0){
		perror("Setting O_NONBLOCK on connection fd");
		exit(1);
	}
	
	if((nh->data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		exit(1);
	}

#if 0
	if(fcntl(nh->data_fd, F_SETFL, O_NONBLOCK) < 0){
		perror("Setting O_NONBLOCK on data fd");
		exit(1);
	}
#endif

	if(compat_v0) bind_sockets_v0(nh);
	else bind_sockets(nh);

	if(listen(nh->ctl_listen_fd, 15) < 0){
		perror("listen");
		exit(1);
	}
	 

	add_fd(ns, nh->ctl_listen_fd);
	add_fd(ns, nh->data_fd);

	hash_init(nh);

	TAILQ_INSERT_TAIL(&ns->switches, nh, nh_link);
	return nh;
}


struct nethub *find_nethubbyname(struct netjig_state *ns,
				 char *name)
{
  struct nethub *nh;

  for(nh=ns->switches.tqh_first;
      nh;
      nh=nh->nh_link.tqe_next) {

    if(strcasecmp(nh->nh_name, name)==0) {
      break;
    }
  }
  return nh;
}

void create_socket_dir(struct netjig_state *ns)
{
	char tmpbuf[1024];

	if(ns->socketbasedir == NULL) {
		char *tmpdir_env;
		int   fd_file;

		tmpdir_env = getenv("TMPDIR");
		if(tmpdir_env == NULL) {
			tmpdir_env = P_tmpdir;
		}

		snprintf(tmpbuf, sizeof(tmpbuf)-4, "%s/umlXXXXXX", tmpdir_env);
		fd_file = mkstemp(tmpbuf);
		
		if(fd_file == -1) {
			fprintf(stderr, "failed to make tmpdir (last=%s)\n", tmpbuf);
			exit(1);
		}

		strcat(tmpbuf,".d");

		if(mkdir(tmpbuf, 0700) != 0) {
			fprintf(stderr, "failed to mkdir(%s): %s\n",
				tmpbuf, strerror(errno));
			exit(2);
		}
		ns->socketbasedir=strdup(tmpbuf);
		close(fd_file);
	}
}
