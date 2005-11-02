/* FreeS/WAN interfaces management (interfaces.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: interfaces.h,v 1.1 2004/01/06 21:43:47 mcr Exp $
 */

#ifndef _STARTER_INTERFACES_H_
#define _STARTER_INTERFACES_H_

void starter_ifaces_init (void);
int starter_iface_find(char *iface, int af, ip_address *dst, ip_address *nh);
int starter_ifaces_load (char **ifaces, unsigned int omtu, int nat_t);
void starter_ifaces_clear (void);

#endif /* _STARTER_INTERFACES_H_ */

