/*
 * Openswan config file writer (confwrite.c)
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
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


void confwrite_int(FILE *out,
		   struct starter_conn *conn,
		   char   *side,
		   int     context,
		   knf     options,
		   int_set  options_set)
{
    struct keyword_def *k;

    for(k=ipsec_conf_keywords_v2; k->keyname!=NULL; k++) {
	
	if((k->validity & context)!=context) continue;

#if 0
	printf("side: %s  %s validity: %08x & %08x=%08x\n", side,
	       k->keyname, k->validity, context, k->validity&context);
#endif
	
	switch(k->type) {
	case kt_string:
	case kt_appendstring:
	case kt_filename:
	case kt_dirname:
	case kt_rsakey:

	case kt_percent:
	case kt_ipaddr:
	case kt_subnet:
	case kt_idtype:
	case kt_bitstring:
	    continue;

	case kt_time:
	    /* special number */
	    break;

	case kt_bool:
	case kt_invertbool:
	case kt_enum:
	case kt_list:
	case kt_loose_enum:
	    /* special enumeration */
	    continue;
	    break;

	case kt_number:
	    break;
	}

	if(options_set[k->field]) {
	    fprintf(out, "\t%s%s=%d\n",side, k->keyname, options[k->field]);
	}
    }	
}    
		   
void confwrite_str(FILE *out,
		   struct starter_conn *conn,
		   char   *side,
		   int     context,
		   ksf     strings,
		   str_set strings_set)
{
    struct keyword_def *k;

    for(k=ipsec_conf_keywords_v2; k->keyname!=NULL; k++) {
	if((k->validity & context)==0) continue;
	
	switch(k->type) {
	case kt_string:
	case kt_appendstring:
	case kt_filename:
	case kt_dirname:
	    /* these are strings */
	    break; 

	case kt_rsakey:
	case kt_ipaddr:
	case kt_subnet:
	case kt_idtype:
	case kt_bitstring:
	    continue;

	case kt_bool:
	case kt_invertbool:
	case kt_enum:
	case kt_list:
	case kt_loose_enum:
	    /* special enumeration */
	    continue;

	case kt_time:
	    /* special number */
	    continue;

	case kt_percent:
	case kt_number:
	    continue;
	}

	if(strings_set[k->field]) {
	    fprintf(out, "\t%s%s=%s\n",side, k->keyname, strings[k->field]);
	}
    }	
}    
		   
		   
void confwrite_side(FILE *out,
		    struct starter_conn *conn,
		    struct starter_end *end,
		    char   *side)
{
    char databuf[2048];  /* good for a 12288 bit rsa key */
    int  keyingtype;

    if(conn->manualkey) {
	keyingtype=kv_manual;
    } else {
	keyingtype=kv_auto;
    }

    switch(end->addrtype) {
    case KH_NOTSET:
	/* nothing! */
	break;
	
    case KH_DEFAULTROUTE:
	fprintf(out, "\t%s=%%defaultroute\n",side);
	break;
	
    case KH_ANY:
	fprintf(out, "\t%s=%%any\n",side);
	break;
	
    case KH_IFACE:
	fprintf(out, "\t%s=%%iface\n",side);   /* MCR: what does this do? XXX */
	break;
	
    case KH_OPPO:
	fprintf(out, "\t%s=%%opportunistic\n",side);   
	break;
	
    case KH_OPPOGROUP:
	fprintf(out, "\t%s=%%opportunisticgroup\n",side);   
	break;
	
    case KH_GROUP:
	fprintf(out, "\t%s=%%group\n",side);   
	break;

    case KH_IPADDR:
	addrtot(&end->addr, 0, databuf, ADDRTOT_BUF);
	fprintf(out, "\t%s=%s\n", side, databuf);
	break;
    }

    if(end->id) {
	fprintf(out, "\t%sid=\"%s\"\n",     side, end->id);
    }

    if(!isanyaddr(&end->nexthop)) {
	addrtot(&end->nexthop, 0, databuf, ADDRTOT_BUF);
	fprintf(out, "\t%snextop=%s\n", side, databuf);
    }

    if(end->has_client) {
	subnettot(&end->subnet, 0, databuf, SUBNETTOT_BUF);
	fprintf(out, "\t%ssubnet=%s\n", side, databuf);
    }

    if(end->rsakey1) {
	fprintf(out, "\t%srsakey=%s\n", side, end->rsakey1);
    }

    if(end->rsakey2) {
	fprintf(out, "\t%srsakey2=%s\n", side, end->rsakey2);
    }

    if(end->port || end->protocol) {
	char b2[32];
	
	strcpy(b2, "%any");
	strcpy(databuf, "%any");

	if(end->port) {
	    sprintf(b2, "%u", end->port);
	}
	if(end->protocol) {
	    sprintf(databuf, "%u", end->protocol);
	}
	    
	fprintf(out, "\t%sportproto=%s/%s\n", side,
		b2, databuf);
    }

    if(end->cert) {
	fprintf(out, "\t%scert=%s\n", side, end->cert);
    }

    confwrite_int(out, conn, side,
		  keyingtype|kv_conn|kv_leftright,
		  end->options, end->options_set);
    confwrite_str(out, conn, side,
		  keyingtype|kv_conn|kv_leftright,
		  end->strings, end->strings_set);

}

void confwrite_conn(FILE *out,
		    struct starter_conn *conn)
{
    int  keyingtype;

    if(conn->manualkey) {
	keyingtype=kv_manual;
    } else {
	keyingtype=kv_auto;
    }

    fprintf(out,"# begin conn %s\n",conn->name);
    
    fprintf(out, "conn %s\n", conn->name);
    
    if(conn->alsos) 
    { /* handle also= as a comment */
	
	int alsoplace=0;
	fprintf(out, "\t#also = ");
	while(conn->alsos[alsoplace] != NULL)
	{
	    fprintf(out, "%s ", conn->alsos[alsoplace]);
	    alsoplace++;
	}
	fprintf(out, "\n");
    }
    confwrite_side(out, conn, &conn->left,  "left");
    confwrite_side(out, conn, &conn->right, "right");
    confwrite_int(out, conn, "", keyingtype|kv_conn,
		  conn->options, conn->options_set);
    confwrite_str(out, conn, "", keyingtype|kv_conn,
		  conn->strings, conn->strings_set);

    if(conn->manualkey) {
	fprintf(out, "\tmanual=add\n");
    } else {
	switch(conn->desired_state) {
	case STARTUP_NO:
	    fprintf(out, "\tauto=ignore\n");
	    break;

	case STARTUP_POLICY:
	    fprintf(out, "\tauto=policy\n");
	    break;
	    
	case STARTUP_ADD:
	    fprintf(out, "\tauto=add\n");
	    break;
	    
	case STARTUP_ROUTE:
	    fprintf(out, "\tauto=route\n");
	    break;
	    
	case STARTUP_START:
	    fprintf(out, "\tauto=start\n");
	    break;
	}
    }

    if(conn->policy) {
	int auth_policy;

	if(conn->policy & POLICY_TUNNEL) {
	    fprintf(out, "\ttype=tunnel\n");
	} else {
	    fprintf(out, "\ttype=transport\n");
	}

	if(conn->policy & POLICY_COMPRESS) {
	    fprintf(out, "\tcompress=yes\n");
	} else {
	    fprintf(out, "\tcompress=no\n");
	}

	if(conn->policy & POLICY_PFS) {
	    fprintf(out, "\tpfs=yes\n");
	} else {
	    fprintf(out, "\tpfs=no\n");
	}

	if(conn->policy & POLICY_DONT_REKEY) {
	    fprintf(out, "\tnorekey=yes\n");
	} else {
	    fprintf(out, "\tnorekey=no\n");
	}

	auth_policy=(conn->policy & POLICY_ID_AUTH_MASK);
	switch(auth_policy) {
	case POLICY_PSK:
	    fprintf(out, "\tauthby=secret\n");
	    break;
	    
	case POLICY_RSASIG:
	    fprintf(out, "\tauthby=rsasig\n");
	    break;

	default:
	    fprintf(out, "\tauthby=never\n");
	    break;
	}
    }

    
    fprintf(out,"# end conn %s\n\n",conn->name);
}

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
	    confwrite_conn(out, conn);
	}
	fprintf(out,"# end of config\n");
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset:4
 * End:
 */
