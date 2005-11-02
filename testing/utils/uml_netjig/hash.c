/* Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>

#include "nethub.h"
#include "switch.h"
#include "hash.h"

struct hash_entry {
  struct hash_entry *next;
  struct hash_entry *prev;
  time_t last_seen;
  void *port;
  unsigned char dst[ETH_ALEN];
};

static int calc_hash(char *src)
{
  return ((*(u_int32_t *) &src[0] % HASH_MOD) ^ src[4] ^ src[5] ) % HASH_SIZE ;
}

static struct hash_entry *find_entry(struct nethub *nh,
				     char *dst)
{
  struct hash_entry *e;
  int k = calc_hash(dst);

  for(e = nh->h[k]; e; e = e->next){
    if(!memcmp(&e->dst, dst, ETH_ALEN)) return(e);
  }
  return(NULL);  
}

void *find_in_hash(struct nethub *nh,
		   char *dst)
{
  struct hash_entry *e = find_entry(nh, dst);
  if(e == NULL) return(NULL);
  return(e->port);
}

void insert_into_hash(struct nethub *nh,
		      char *src, void *port)
{
  struct hash_entry *new;
  int k = calc_hash(src);

  new = find_in_hash(nh, src);
  if(new != NULL) return;

  new = malloc(sizeof(*new));
  if(new == NULL){
    perror("Failed to malloc hash entry");
    return;
  }

  memcpy(&new->dst, src, ETH_ALEN );
  if(nh->h[k] != NULL) nh->h[k]->prev = new;
  new->next = nh->h[k];
  new->prev = NULL;
  new->port = port;
  new->last_seen = 0;
  nh->h[k] = new;
}

void update_entry_time(struct nethub *nh,
		       char *src)
{
  struct hash_entry *e;

  e = find_entry(nh, src);
  if(e == NULL) return;
  e->last_seen = time(NULL);
}

static void delete_hash_entry(struct nethub *nh,
			      struct hash_entry *old)
{
  int k = calc_hash(old->dst);

  if(old->prev != NULL) old->prev->next = old->next;
  if(old->next != NULL) old->next->prev = old->prev;
  if(nh->h[k] == old) nh->h[k] = old->next;
  free(old);
}

void delete_hash(struct nethub *nh,
		 char *dst)
{
  struct hash_entry *old = find_entry(nh, dst);

  if(old == NULL) return;
  delete_hash_entry(nh, old);
}

static void for_all_hash(struct nethub *nh,
			 void (*f)(struct nethub *nh,
				   struct hash_entry *,
				   void *),
			 void *arg)
{
  int i;
  struct hash_entry *e, *next;

  for(i = 0; i < HASH_SIZE; i++){
    for(e = nh->h[i]; e; e = next){
      next = e->next;
      (*f)(nh, e, arg);
    }
  }
}

struct printer {
  time_t now;
  char *(*port_id)(void *);
};

static void print_hash_entry(struct nethub *nh,
			     struct hash_entry *e, void *arg)
{
  struct printer *p = arg;

  fprintf(stderr, "Hash: %d Addr: %02x:%02x:%02x:%02x:%02x:%02x to port: %s  " 
	  "age %ld secs\n", calc_hash(e->dst),
	  e->dst[0], e->dst[1], e->dst[2], e->dst[3], e->dst[4], e->dst[5],
	  (*p->port_id)(e->port), (int) p->now - e->last_seen);
}

void print_hash(struct nethub *nh,
		char *(*port_id)(void *))
{
  struct printer p = ((struct printer) { now : 		time(NULL),
					 port_id :	port_id });

  for_all_hash(nh, print_hash_entry, &p);
}

static void gc(struct nethub *nh,
	       struct hash_entry *e,
	       void *now)
{
  time_t t = *(time_t *) now;

  if(e->last_seen + GC_EXPIRE < t)
    delete_hash_entry(nh, e);
}

void hash_periodic(struct nethub *nh)
{
  time_t t = time(NULL);
  for_all_hash(nh, &gc, &t);
}
  
void hash_init(struct nethub *nh)
{
  /* nothing right now */
}
