/* Copyright 2001, 2002 Jeff Dike and others
 * Licensed under the GPL
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <unistd.h>

#include "nethub.h"
#include "switch.h"
#include "port.h"
#include "hash.h"
#ifdef TUNTAP
#include "tuntap.h"
#endif


#ifdef notdef
#include <stddef.h>
#endif

static char *ctl_socket = "/tmp/uml.ctl";
static char *data_socket = NULL;

char *progname;

static struct nethub *global_nh = NULL;
static struct netjig_state *global_ns=NULL;

static void cleanup(void)
{
  if(global_nh) {
    cleanup_nh(global_nh);
  }
}

static void sig_handler(int sig)
{
  fprintf(stderr, "Caught signal %d, cleaning up and exiting\n", sig);
  cleanup();
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

void *xmalloc1(size_t size, char *file, int linenum)
{
	void *space;

	space = malloc(size);
	if(space == NULL) {
		fprintf(stderr, "no memory allocating %d bytes at %s:%d\n",
			size, file, linenum);
		exit(1);
	}
	return space;
}


static void Usage(void)
{
  fprintf(stderr, "Usage : %s [ -unix control-socket ] [ -hub ]\n"
	  "or : %s -compat-v0 [ -unix control-socket data-socket ] [ -hub ]\n"
	  "or : %s -name switch [ -hub ]\n",
	  progname, progname, progname);
  exit(1);
}

static void sig_alarm(int sig)
{
  struct itimerval it;

  hash_periodic(global_nh);

  it.it_value.tv_sec = GC_INTERVAL;
  it.it_value.tv_usec = 0 ;
  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 0 ;
  setitimer(ITIMER_REAL, &it, NULL);
}

void hash_timer_init()
{
  struct sigaction sa;

  sa.sa_handler = sig_alarm;
  sa.sa_flags = SA_RESTART;
  if(sigaction(SIGALRM, &sa, NULL) < 0){
    perror("Setting handler for SIGALRM");
    return;
  }
  kill(getpid(), SIGALRM);
}

int main(int argc, char **argv)
{
  int hub, compat_v0;
  int n, i;
  char *tap_dev = NULL;
  char *home;
  char *switchname;
  int            *l_fd_array;
  int             l_fd_array_size;  /* so we can grow it in add_fd() */
  struct pollfd  *l_fds;        /* array of input sources */
  int             l_nfds;       /* number of relevant entries */

  hub = 0;
  compat_v0=0;
  switchname="switch";

  global_ns = malloc(sizeof(*global_ns));
  memset(global_ns, 0, sizeof(*global_ns));
  TAILQ_INIT(&global_ns->switches);

  progname = argv[0];
  argv++;
  argc--;
  while(argc > 0){
    if(!strcmp(argv[0], "-unix")){
      if(argc < 2) Usage();
      ctl_socket = argv[1];
      argc -= 2;
      argv += 2;
      if(!compat_v0) break;
      if(argc < 1) Usage();
      data_socket = argv[0];
      argc--;
      argv++;
    }
    else if(!strcmp(argv[0], "-name")){
      if(argc < 2) Usage();
      switchname = argv[1];
      ctl_socket=NULL;
      data_socket=NULL;
      argc -= 2;
      argv += 2;
    }
    else if(!strcmp(argv[0], "-tap")){
#ifdef TUNTAP
      tap_dev = argv[1];
      argv += 2;
      argc -= 2;
#else
      fprintf(stderr, "-tap isn't supported since TUNTAP isn't enabled\n");
      Usage();
#endif      
    }
    else if(!strcmp(argv[0], "-hub")){
      printf("%s will be a hub instead of a switch\n", progname);
      hub = 1;
      argc--;
      argv++;
    }
    else if(!strcmp(argv[0], "-compat-v0")){
      printf("Control protocol 0 compatibility\n");
      compat_v0 = 1;
      data_socket = "/tmp/uml.data";
      argc--;
      argv++;
    }
    else Usage();
  }

  /* set socket base dir to $HOME/.uml, defaulting back to /tmp/uml,
   * if $HOME is not set.
   */
  if((home=getenv("HOME"))==NULL) {
    global_ns->socketbasedir="/tmp/uml";
  } else {
    global_ns->socketbasedir=xmalloc(strlen(home)+1+sizeof(".umlnet")+1);
    sprintf(global_ns->socketbasedir,
	    "%s/.umlnet", home);
  }

  global_nh = init_nethub(global_ns,
			  switchname,
			  ctl_socket,
			  data_socket,
			  compat_v0);
  global_nh->nh_hub = hub;
  
  if(signal(SIGINT, sig_handler) < 0)
    perror("Setting handler for SIGINT");
  hash_timer_init();

  if(compat_v0) 
    printf("%s attached to unix sockets '%s' and '%s'\n",
 	   progname,
	   global_nh->ctl_socket_name,
	   (global_nh->data_socket_name ?
	    global_nh->data_socket_name : "-abstract-named-"));
  else printf("%s attached to unix socket '%s'\n",
	      progname,
	      global_nh->ctl_socket_name);

  if(isatty(0)) add_fd(global_ns, 0);

#ifdef TUNTAP
  if(tap_dev != NULL) {
    global_nh->tap_fd = open_tap(global_ns, global_nh, tap_dev);
  }
#endif

  l_fd_array = NULL;
  l_fd_array_size = 0;
  l_fds = NULL;
  l_nfds= 0;

  while(1){
    char buf[128];

    /*
     * we need to allocate a local copy of the arrays to use!
     * since we are going to modify the arrays based upon I/O
     */
    if(l_nfds != global_ns->nfds) {
	    l_nfds = global_ns->nfds;
	    l_fds = realloc(l_fds, l_nfds * sizeof(struct pollfd));
    }
    memcpy(l_fds,      global_ns->fds,      l_nfds * sizeof(struct pollfd));
    if(l_fd_array_size != global_ns->fd_array_size) {
	    l_fd_array_size = global_ns->fd_array_size;
	    l_fd_array = realloc(l_fd_array, l_fd_array_size*sizeof(int));
    }
    memcpy(l_fd_array, global_ns->fd_array, l_fd_array_size * sizeof(int));
    
    n = poll(l_fds, l_nfds, -1);
    if(n < 0){
      if(errno == EINTR) continue;
      perror("poll");
      break;
    }
    for(i = 0; i < l_nfds; i++){
      if(l_fds[i].revents == 0) continue;
      if(l_fds[i].fd == 0){
	if(l_fds[i].revents & POLLHUP){
	  printf("EOF on stdin, cleaning up and exiting\n");
	  goto out;
	}
	n = read(0, buf, sizeof(buf));
	if(n < 0){
	  perror("Reading from stdin");
	  break;
	}
	else if(n == 0){
	  printf("EOF on stdin, cleaning up and exiting\n");
	  goto out;
	}
      }
      else if(l_fds[i].fd == global_nh->ctl_listen_fd){
	if(l_fds[i].revents & POLLHUP){
	  printf("Error on connection fd\n");
	  continue;
	}
	accept_connection(global_ns, global_nh);
      }
      else if(l_fds[i].fd == global_nh->data_fd) {
	handle_sock_data(global_ns, global_nh);
      }
#ifdef TUNTAP
      else if(l_fds[i].fd == global_nh->tap_fd) {
	handle_tap_data(global_ns, global_nh);
      }
#endif
      else {
	handle_port(global_ns, global_nh,
		    l_fds, l_nfds,
		    l_fd_array, l_fd_array_size);
      }
    }
  }
 out:
  cleanup();
  return 0;
}
