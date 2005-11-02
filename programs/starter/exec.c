/* FreeS/WAN exec helper function (exec.c)
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
 * RCSID $Id: exec.c,v 1.3 2004/01/20 20:47:42 mcr Exp $
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "exec.h"
#include "starterlog.h"

#define BUFF_SIZE  2048

/**
 * TODO:
 * o log stdout with LOG_LEVEL_INFO and stderr with LOG_LEVEL_ERR
 */

int starter_exec (const char *fmt, ...)
{
	va_list args;
	static char buff[BUFF_SIZE];
	int r;

	va_start (args, fmt);
	vsnprintf(buff, BUFF_SIZE-1, fmt, args);
	buff[BUFF_SIZE-1] = '\0';
	va_end(args);
	
	if(showonly)
	{
	    starter_log(LOG_LEVEL_INFO, "showonly: invoking %s", buff);
	    r = 0;
	}
	else
	{
	    r = system(buff);
	    starter_log(LOG_LEVEL_DEBUG, "starter_exec(%s) = %d", buff, r);
	} 
	return r;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
