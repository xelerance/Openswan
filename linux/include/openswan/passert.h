/*
 * sanitize a string into a printable format.
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003  Michael Richardson <mcr@freeswan.org>
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
 *
 * RCSID $Id: passert.h,v 1.4 2004/04/06 02:49:08 mcr Exp $
 */

#include "openswan.h"

/* our versions of assert: log result */

#ifdef DEBUG

extern void passert_fail(const char *pred_str
    , const char *file_str, unsigned long line_no) NEVER_RETURNS;

extern void pexpect_log(const char *pred_str
			, const char *file_str, unsigned long line_no);

# define impossible() passert_fail("impossible", __FILE__, __LINE__)

extern void switch_fail(int n
    , const char *file_str, unsigned long line_no) NEVER_RETURNS;

# define bad_case(n) switch_fail((int) n, __FILE__, __LINE__)

# define passert(pred) { \
	if (!(pred)) \
	    passert_fail(#pred, __FILE__, __LINE__); \
    }

# define pexpect(pred) { \
	if (!(pred)) \
	    pexpect_log(#pred, __FILE__, __LINE__); \
    }

/* assert that an err_t is NULL; evaluate exactly once */
# define happy(x) { \
	err_t ugh = x; \
	if (ugh != NULL) \
	    passert_fail(ugh, __FILE__, __LINE__); \
    }

#else /*!DEBUG*/

# define impossible() abort()
# define bad_case(n) abort()
# define passert(pred)  { }	/* do nothing */
# define happy(x)  { (void) x; }	/* evaluate non-judgementally */

#endif /*!DEBUG*/

