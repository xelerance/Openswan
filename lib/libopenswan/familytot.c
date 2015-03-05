/*
 * special addresses
 * Copyright (C) 2000  Henry Spencer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include "openswan.h"
#include "libopenswan.h"

/*
 - familyname - return the family for an address.
 */
const char *family2str(unsigned int family)
{
  static char inetnamebuf[64];

  switch (family) {
  case AF_INET:
    return "inet";

  case AF_INET6:
    return "inet6";

  default:
    sprintf(inetnamebuf, "family:%u", family);
    return inetnamebuf;
  }
}
