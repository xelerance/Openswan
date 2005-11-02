/* Copyright 2002 Yon Uriarte and Jeff Dike
 * Licensed under the GPL
 */

#ifndef __HASH_H__
#define __HASH_H__

struct nethub;

extern void *find_in_hash(struct nethub *nh, char *dst);
extern void insert_into_hash(struct nethub *nh, char *src, void *port);
extern void delete_hash(struct nethub *nh, char *dst);
extern void print_hash(struct nethub *nh,
		       char *(*port_id)(void *));
extern void update_entry_time(struct nethub *nh, char *src);
extern void hash_init(struct nethub *nh);
extern void hash_periodic(struct nethub *nh);

#define GC_INTERVAL 2
#define GC_EXPIRE 100

#endif
