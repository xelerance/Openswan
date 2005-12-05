/* misc functions to get compile time and runtime options
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: oswalloc.h,v 1.3 2004/10/16 23:42:13 mcr Exp $
 */

#ifndef _OSW_CONF_H
#define _OSW_CONF_H

#include "constants.h"

struct osw_conf_options {
    char *confdir;                /* "/etc" */
    char *conffile;               /* "/etc/ipsec.conf" */
    char *confddir;               /* "/etc/ipsec.d" */
    char *vardir;                 /* "/var/run/pluto" */
};

extern const struct osw_conf_options *osw_init_options(void);

#endif /* _OSW_ALLOC_H_ */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
