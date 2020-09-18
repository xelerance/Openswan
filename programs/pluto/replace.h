/* handling SA state replacement/expiration
 * Copyright (C) 2019  Bart Trojanowski
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
 */

#ifndef _REPLACE_H
#define _REPLACE_H
#include "oswtime.h"

struct state;

extern void sa_replace(struct state *st, int type);
extern void sa_expire(struct state *st);
extern void schedule_sa_replace_event(bool is_initiator, unsigned long delay,
                                      struct connection *c, struct state *st);

#endif /* _TIMER_H */

