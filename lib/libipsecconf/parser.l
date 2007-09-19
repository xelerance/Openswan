/* -*- flex-mode -*- */
%option nounput
%{ 
/* FreeS/WAN config file parser (parser.l)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
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

#include <sys/queue.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <glob.h>

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"
#include "parser.tab.h"
#include "ipsecconf/parserlast.h"
#include "ipsecconf/starterlog.h"

#define MAX_INCLUDE_DEPTH  10

char rootdir[PATH_MAX];      /* when evaluating paths, prefix this to them */
char rootdir2[PATH_MAX];     /* or... try this one too */


/* we want no actual output! */
#define ECHO 

/*    
#define YY_NO_UNPUT
*/

extern void yyerror(const char *);

extern int yylex (void);
extern int yydebug;
extern int verbose;
    
struct ic_inputsource {
	YY_BUFFER_STATE state;
	FILE  *file;
	unsigned int line;
	char  *filename;
	int    fileglobcnt;
	glob_t fileglob;
};
	
static struct {
	int stack_ptr;
	struct ic_inputsource stack[MAX_INCLUDE_DEPTH];
} ic_private;

static struct ic_inputsource *stacktop;

char *parser_cur_filename(void)
{
    return stacktop->filename;
}

int  parser_cur_lineno(void)
{
    return stacktop->line;
}

void parser_y_error(char *b, int size, const char *s)
{
#if defined(SOMETHING_FOR_SOME_ARCH)
	extern char *yytext;
#endif

	snprintf(b, size, "%s:%d: %s [%s]",
		 stacktop->filename ? stacktop->filename : "<none>",
		 stacktop->line,
		 s, yytext);
}

void parser_y_init (const char *f)
{
	memset(&ic_private, 0, sizeof(ic_private));
	ic_private.stack[0].line = 1;
	ic_private.stack[0].filename = strdup(f);
	stacktop = &ic_private.stack[0];
}

void parser_y_close(struct ic_inputsource *iis)
{
	if (iis->filename)
		free(iis->filename);
	if (iis->file)
		fclose(iis->file);
	if (iis->fileglob.gl_pathv)
		globfree(&iis->fileglob);
}

void parser_y_fini (void)
{
	unsigned int i;

	for (i=0; i<MAX_INCLUDE_DEPTH; i++) {
		parser_y_close(&ic_private.stack[i]);
		
	}
	memset(&ic_private, 0, sizeof(ic_private));
}

int parser_y_nextglobfile(struct ic_inputsource *iis)
{
	FILE *f;
	int  fcnt;

#if 0
	printf("fileglobcnt: %d pathc: %d cmp: %u\n", 
	       iis->fileglobcnt, stacktop->fileglob.gl_pathc,
	       (iis->fileglobcnt >= (int)stacktop->fileglob.gl_pathc));
#endif

	if((int)iis->fileglobcnt >= (int)stacktop->fileglob.gl_pathc) {
		/* EOFiles */
		return -1;
	}

	/* increment for next time  */
	fcnt = iis->fileglobcnt++;

	/* open the file */
	f = fopen(iis->fileglob.gl_pathv[fcnt], "r");
	if (!f) {
                char ebuf[128];
		snprintf(ebuf, 128, "can't open include filename: '%s'", iis->fileglob.gl_pathv[fcnt]);
                yyerror(ebuf);
		return -1;
	}

	if(iis->file) fclose(iis->file);
	if(iis->filename) free(iis->filename);

	iis->file  = f;
	iis->line  = 1;
	iis->filename = strdup(iis->fileglob.gl_pathv[fcnt]);

	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	return 0;
}

int parser_y_include (const char *filename)
{
	char newname[PATH_MAX];
        glob_t globbuf;

	globbuf.gl_offs = 0;

	if(rootdir[0]!='\0' && filename[0]=='/')
        {
	    snprintf(newname, PATH_MAX, "%s%s", rootdir, filename);

            if(access(newname, R_OK)!=0) {
		    if(rootdir2[0]!='\0') {
			    snprintf(newname, PATH_MAX, "%s%s", rootdir2, filename);
		    }
	    }
	    filename=newname;
	}
		
	if(glob(filename, GLOB_BRACE|GLOB_NOMAGIC, NULL, &globbuf) == GLOB_NOMATCH) {
		/* no files found. maybe try rootdir2 now */
                char ebuf[128];

		if(strchr(filename, '*')) {
		   /* be quiet about missing files */
		   return 0;
                }

		snprintf(ebuf, 128, "can't open include filename: '%s'", filename);
                yyerror(ebuf);
		globfree(&globbuf);
		return 1;
	}

	if (ic_private.stack_ptr >= MAX_INCLUDE_DEPTH)
	{
		yyerror("max inclusion depth reached");
		return 1;
	}

	if(verbose)
	{
		starter_log(LOG_LEVEL_DEBUG, "including file '%s' from line %s:%d\n"
			    , filename
			    , stacktop->filename
			    , stacktop->line);
	}

	++ic_private.stack_ptr;
	stacktop = &ic_private.stack[ic_private.stack_ptr];
	stacktop->state = YY_CURRENT_BUFFER;
	stacktop->fileglob = globbuf;
	stacktop->fileglobcnt = 0;
	stacktop->file = NULL;
	stacktop->filename=NULL;

	(void)parser_y_nextglobfile(stacktop);
	
	return 0;
}

int parser_y_eof(void)
{
	yy_delete_buffer(YY_CURRENT_BUFFER);

	if(parser_y_nextglobfile(stacktop) == -1) {
		/* no more glob'ed files to process */
		
		if(verbose)
		{
			int stackp = ic_private.stack_ptr;
			starter_log(LOG_LEVEL_DEBUG,
				    "end of file %s, resuming %s line %d\n"
				    , stacktop->filename
				    , (stackp > 0 ? ic_private.stack[stackp-1].filename : "<none>")
				    , (stackp > 0 ? ic_private.stack[stackp-1].line : -1));
		}
		
		yy_switch_to_buffer(stacktop->state);

		parser_y_close(stacktop);
		
		if (--ic_private.stack_ptr < 0) {
			return 1;
		}
		stacktop = &ic_private.stack[ic_private.stack_ptr];
	}
	return 0;
}

%}

%x USERDEF BOOLEAN COMMENTEQUAL COMMENTSTRING

%%

<<EOF>>	{
	if(parser_y_eof()) {
		yyterminate();
	}
}

^\n		        { /* eat totally blank lines */
                          stacktop->line++;
		        }

^#.*\n		        { /* eat comment lines */
                          stacktop->line++;
		        }

^[\t ]+#.*\n            { /* eat comment lines inside of stanzas */
                          stacktop->line++;
		        }

^[\t ]+\n		/* ignore lines that just have combinations of spaces on them */

^[\t ]+			return FIRST_SPACES;

[\t ]+			/* ignore spaces in line */ ;

<USERDEF>[0-9]+         { /* process a number */
                           yylval.num = atof(yytext);
                           BEGIN INITIAL;
			   return INTEGER;
                        }

<USERDEF>%forever       { /* a number, really 0 */
                           yylval.num = 0;
                           BEGIN INITIAL;
			   return INTEGER;
			}

<USERDEF>[0-9]+\.[0-9]* { /* process a number */
                           yylval.dblnum = atof(yytext);
                           BEGIN INITIAL;
			   return NUMBER;
                        }

[0-9]+                  { /* process a number */
                           yylval.num = atof(yytext);
                           BEGIN INITIAL;
			   return INTEGER;
                        }

[0-9]+\.[0-9]*          { /* process a number */
                           yylval.dblnum = atof(yytext);
                           BEGIN INITIAL;
			   return NUMBER;
                        }

<BOOLEAN>y   |
<BOOLEAN>yes |
<BOOLEAN>true |
<BOOLEAN>on             { /* process a boolean */
                          yylval.num = 1;
                          BEGIN INITIAL;
			  return BOOL;
			}

<BOOLEAN>n   |
<BOOLEAN>no  |
<BOOLEAN>false |
<BOOLEAN>off            { /* process a boolean */
                          yylval.num = 0;
                          BEGIN INITIAL;
			  return BOOL;
                        }
  
<BOOLEAN>=		return EQUAL;

<BOOLEAN>\n 	        {
                          stacktop->line++;
			  BEGIN INITIAL;
			  return EOL;
		        }

<COMMENTEQUAL>=        {
                            BEGIN COMMENTSTRING;
                            return EQUAL;
                        }

<COMMENTSTRING>[^\n]*   {
                            yylval.s = strdup(yytext);
                            BEGIN INITIAL;
                            return STRING;
                        }

<USERDEF>\"[^\"\n]*\"	{
                           char *s = yytext + 1;
			   int len = strlen(s);

			   assert(len>0);

			   /* remove trailing " */
			   s[len-1]='\0'; 
			   if(yydebug) { fprintf(stderr, "STRING: \"%s\"\n", s);}
			   yylval.s = strdup(s);
			   BEGIN INITIAL;
                           return STRING;
			}

<USERDEF>\{[^\"\n]*\}	{
                           char *s = yytext + 1;
			   int len = strlen(s);

			   assert(len>0);

			   /* remove trailing } */
			   s[len-1]='\0'; 
			   if(yydebug) { fprintf(stderr, "STRING{}: {%s}\n", s);}
			   yylval.s = strdup(s);
			   BEGIN INITIAL;
                           return STRING;
			}

<USERDEF>[^\" \t\n]+   {
			   yylval.s = strdup(yytext);
			   BEGIN INITIAL;
                           return STRING;
			}

<USERDEF>[^\{} \t\n]+   {
			   yylval.s = strdup(yytext);
			   BEGIN INITIAL;
                           return STRING;
			}

\n  		        {
                          stacktop->line++;
			  return EOL;
		        }

=			{ BEGIN USERDEF; return EQUAL; }
version                 return VERSION;     
config			return CONFIG; 
setup			return SETUP;
conn			{ BEGIN USERDEF; return CONN; }
include			return INCLUDE;

[^\"= \t\n]+	        {  int tok;
    
                           if(yydebug) { fprintf(stderr, "STR/KEY: %s\n", yytext); }
                           tok = parser_find_keyword(yytext, &yylval);
			   switch(tok)
			   {
			   case BOOLWORD:
			       BEGIN BOOLEAN;
			       break;
                           case COMMENT:
			       BEGIN COMMENTEQUAL;
                               break;
			   default:
                               break;
			   }
			   return tok;
			}

#.*		        /* eat comment lines */ {
                        }

.			yyerror(yytext);
%%

int yywrap(void) {
	return 1;
}

/*
 * Local Variables:
 * mode: flex
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
