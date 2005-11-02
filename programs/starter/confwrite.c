/* FreeS/WAN config file writer (confwrite.c)
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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
 * RCSID $Id: confwrite.c,v 1.1 2004/02/05 17:23:30 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/queue.h>

#include "parser.h"
#include "confread.h"
#include "interfaces.h"
#include "starterlog.h"

void confwrite(struct starter_config *cfg, FILE *out)
{
	struct starter_conn *conn;

	/* output version number */
	fprintf(out, "version 2.0\n");

	/* output config setup section */

	/* output connections */
	for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
	{
	    struct keyword_def *kd;

	    fprintf(out, "conn %s\n", conn->name);

	    { /* handle also= as a comment */
		
		int alsoplace=0;
		fprintf(out, "\t#also = ");
		while(conn->alsos != NULL
		      && conn->alsos[alsoplace] != NULL 
		      && alsoplace < ALSO_LIMIT)
		{
		    fprintf(out, "%s ", conn->alsos[alsoplace]);
		}
		fprintf(out, "\n");
	    }

	    kd = ipsec_conf_keywords_v2;
	    while(kd->keyname != NULL)
	    {
		/* skip keywords that do not apply to conns */
		if(!(kd->validity & kv_conn)) continue;

		switch(kd->type)
		{
		case kt_string:
		case kt_appendstring:
		case kt_filename:
		case kt_dirname:
		case kt_bool:
		case kt_invertbool:
		case kt_enum:
		case kt_list:
		case kt_loose_enum:
		case kt_rsakey:
		case kt_number:
		case kt_time:
		case kt_percent:
		case kt_ipaddr:
		case kt_subnet:
		case kt_idtype:
		case kt_bitstring:
		}


	    for(i=0; i<sizeof(ipsec_conf_keywords_v2)/sizeof(struct keyword_def); i++)
	    {
		
		
		


	}
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset:4
 * End:
 */
