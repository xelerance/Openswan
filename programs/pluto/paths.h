/* Openswan ISAKMP path handling
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
 * RCSID $Id: paths.h,v 1.1 2003/12/24 19:51:21 mcr Exp $
 */

#ifndef _PATHS_H_
#define _PATHS_H_

struct paththing {
  char    *path;
  size_t   path_space;
};

struct pluto_paths {
  struct paththing acerts;
  struct paththing cacerts;
  struct paththing crls;
  struct paththing private;
  struct paththing certs;
};

/* defined in log.c */
extern const char *ipsec_dir;
extern void set_paths(const char *basedir);
extern void verify_path_space(struct paththing *p, size_t min, const char *why);

extern struct pluto_paths plutopaths;

#endif
