/* parse pluto configuration command line options
 * Copyright (C) 2021 Michael Richardson <mcr@sandelman.ca>
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
 */

#ifndef _PLUTO_OPTS_H
#define _PLUTO_OPTS_H

#include "oswalloc.h"

extern void pluto_usage(const char *mess);
extern err_t pluto_options_process(int argc, char **argv, chunk_t *encode_opts);


#endif /* _PLUTO_OPTS_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
