/* misc. universal things
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: alloc.c,v 1.1 2004/04/18 03:03:28 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <openswan.h>

#include "constants.h"
#include "oswalloc.h"

const chunk_t empty_chunk = { NULL, 0 };

exit_log_func_t exit_log_func;

void set_exit_log_func(exit_log_func_t func)
{
    exit_log_func = func;
}

bool
all_zero(const unsigned char *m, size_t len)
{
    size_t i;

    for (i = 0; i != len; i++)
	if (m[i] != '\0')
	    return FALSE;
    return TRUE;
}

/* memory allocation
 *
 * LEAK_DETECTIVE puts a wrapper around each allocation and maintains
 * a list of live ones.  If a dead one is freed, an assertion MIGHT fail.
 * If the live list is currupted, that will often be detected.
 * In the end, report_leaks() is called, and the names of remaining
 * live allocations are printed.  At the moment, it is hoped, not that
 * the list is empty, but that there will be no surprises.
 *
 * Accepted Leaks:
 * - "struct iface" and "device name" (for "discovered" net interfaces)
 * - "struct event in event_schedule()" (events not associated with states)
 * - "Pluto lock name" (one only, needed until end -- why bother?)
 */

#ifdef LEAK_DETECTIVE

/* this magic number is 3671129837 decimal (623837458 complemented) */
#define LEAK_MAGIC 0xDAD0FEEDul

union mhdr {
    struct {
	const char *name;
	union mhdr *older, *newer;
	unsigned long magic;
    } i;    /* info */
    unsigned long junk;	/* force maximal alignment */
};

static union mhdr *allocs = NULL;

void *alloc_bytes(size_t size, const char *name)
{
    union mhdr *p = malloc(sizeof(union mhdr) + size);

    if (p == NULL)
	exit_log("unable to malloc %lu bytes for %s"
	    , (unsigned long) size, name);
    p->i.name = name;
    p->i.older = allocs;
    if (allocs != NULL)
	allocs->i.newer = p;
    allocs = p;
    p->i.newer = NULL;
    p->i.magic = LEAK_MAGIC;

    memset(p+1, '\0', size);
    return p+1;
}

void *
clone_bytes(const void *orig, size_t size, const char *name)
{
    void *p = alloc_bytes(size, name);

    memcpy(p, orig, size);
    return p;
}

void
pfree(void *ptr)
{
    union mhdr *p;

    passert(ptr != NULL);
    p = ((union mhdr *)ptr) - 1;
    passert(p->i.magic == LEAK_MAGIC);
    if (p->i.older != NULL)
    {
	passert(p->i.older->i.newer == p);
	p->i.older->i.newer = p->i.newer;
    }
    if (p->i.newer == NULL)
    {
	passert(p == allocs);
	allocs = p->i.older;
    }
    else
    {
	passert(p->i.newer->i.older == p);
	p->i.newer->i.older = p->i.older;
    }
    p->i.magic = ~LEAK_MAGIC;
    free(p);
}

void
report_leaks(void)
{
    union mhdr
	*p = allocs,
	*pprev = NULL;
    unsigned long n = 0;

    while (p != NULL)
    {
	passert(p->i.magic == LEAK_MAGIC);
	passert(pprev == p->i.newer);
	pprev = p;
	p = p->i.older;
	n++;
	if (p == NULL || pprev->i.name != p->i.name)
	{
	    if (n != 1)
		plog("leak: %lu * %s", n, pprev->i.name);
	    else
		plog("leak: %s", pprev->i.name);
	    n = 0;
	}
    }
}

#else /* !LEAK_DETECTIVE */

void *alloc_bytes(size_t size, const char *name)
{
    void *p = malloc(size);

    if (p == NULL) {
	if(exit_log_func) {
	    (*exit_log_func)("unable to malloc %lu bytes for %s"
			     , (unsigned long) size, name);
	}
    }
    memset(p, '\0', size);
    return p;
}

void *clone_bytes(const void *orig, size_t size, const char *name)
{
    void *p = malloc(size);

    if (p == NULL) {
	if(exit_log_func) {
	    (*exit_log_func)("unable to malloc %lu bytes for %s"
			     , (unsigned long) size, name);
	}
    }
    memcpy(p, orig, size);
    return p;
}
#endif /* !LEAK_DETECTIVE */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */


