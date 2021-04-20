/* whack communicating routines
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

#ifndef _RCV_WHACK_H
#define _RCV_WHACK_H
#include "oswconf.h"

extern err_t whack_decode_and_process(int whack_fd, chunk_t *encode_msg);
extern err_t pluto_set_coredir(struct osw_conf_options *oco);
extern void whack_process(int whackfd, struct whack_message msg);
extern void whack_handle(int kernelfd);
extern void whack_listen(void);

#endif /* _RCV_WHACK_H */

