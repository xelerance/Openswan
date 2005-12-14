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
 * RCSID $Id: confwrite.c,v 1.5 2004/12/07 00:28:18 ken Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/queue.h>

#include "ipsecconf/parser.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/keywords.h"

void confwrite(struct starter_config *cfg, FILE *out)
{
	struct starter_conn *conn;
/*	int i;
*/
	/* output version number */
	fprintf(out, "version 2.0\n");

	/* output config setup section */

	/* output connections */
	for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
	{
	    struct keyword_def *k;

            fprintf(out,"# begin conn %s\n",conn->name);

	    fprintf(out, "conn %s\n", conn->name);

	    { /* handle also= as a comment */
		
		int alsoplace=0;
		fprintf(out, "\t#also = ");
		while(conn->alsos != NULL
		      && conn->alsos[alsoplace] != NULL 
		      && alsoplace < ALSO_LIMIT)
		{
		    fprintf(out, "%s ", conn->alsos[alsoplace]);
		    alsoplace++;
		}
		fprintf(out, "\n");
	    }
	    fprintf(out,"# Completed alsos\n");
	    k = ipsec_conf_keywords_v2;
	    while(k->keyname != NULL)
	    {
		fprintf(out,"keyname = %s\n",k->keyname);

		/* skip keywords that do not apply to conns */
/*		if(!(k->validity & kv_conn)) continue; */

		switch(k->type)
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
		break;
		}

/*	        for(i=0; i< ipsec_conf_keywords_v2_count; i++)
	        {
			fprintf(out,"%d of %d\n",i, ipsec_conf_keywords_v2_count);
                }
*/
	    k++; 
            }
            fprintf(out,"# end conn %s\n",conn->name);
	}
	fprintf(out,"# end of config\n");
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset:4
 * End:
 */
