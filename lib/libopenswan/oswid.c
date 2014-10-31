/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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

#include "oswalloc.h"
#include "constants.h"
#include "id.h"
#include "openswan/ipsec_policy.h"

enum myid_state myid_state = MYID_UNKNOWN;
struct id myids[MYID_SPECIFIED+1];	/* %myid */

const struct id *resolve_myid(const struct id *id)
{
  if((id)->kind == ID_MYID) {
    return &myids[myid_state];
  } else {
    return (id);
  }
}
