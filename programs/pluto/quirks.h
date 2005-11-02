/* FreeS/WAN ISAKMP Quirks handling
 * Copyright (C) 2003 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: quirks.h,v 1.2 2003/12/24 19:51:21 mcr Exp $
 */

#ifndef _QUIRKS_H_
#define _QUIRKS_H_

struct isakmp_quirks {
  bool xauth_ack_msgid;         /* whether to reset the msgid after an
				 * xauth set, such as for SSH Sentinel. */
  unsigned short nat_traversal_vid;  /* which NAT-type vendor IDs we got */
};

#endif
