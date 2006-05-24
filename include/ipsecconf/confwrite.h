/* Openswan config file writer (confwrite.h)
 * Copyright (C) 2004 Xelerance Corporation
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
 * RCSID $Id: confwrite.h,v 1.1 2004/11/29 20:35:32 ken Exp $
 */

#ifndef _IPSEC_CONFWRITE_H_
#define _IPSEC_CONFWRITE_H_

#include "keywords.h"

#ifndef _OPENSWAN_H
#include "openswan.h"
#include "constants.h"
#endif

void confwrite_list(FILE *out, char *prefix, int val, struct keyword_def *k);
void confwrite(struct starter_config *cfg, FILE *out);


#endif /* _IPSEC_CONFWRITE_H_ */

