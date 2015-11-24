%{   /* -*- bison-mode -*- */
/* FreeS/WAN config file parser (parser.y)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
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
 */

#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"
#include "ipsecconf/confread.h"

#define YYDEBUG 1
#define YYERROR_VERBOSE
#define ERRSTRING_LEN	256

/**
 * Bison
 */
static char parser_errstring[ERRSTRING_LEN+1];
void yyerror(const char *s);
extern int yylex (void);
static struct kw_list *alloc_kwlist(void);
static struct starter_comments *alloc_comment(void);
static void process_keyword_equal(struct keyword kw, struct kw_list *new, const char *const_string);

/**
 * Static Globals
 */
static int _save_errors_;
static struct config_parsed *_parser_cfg;
static struct kw_list **_parser_kw, *_parser_kw_last;
static struct starter_comments_list *_parser_comments;

/**
 * Functions
 */

%}

%union {
	char *s;
        unsigned int num;
	struct keyword k;
}
%token EQUAL FIRST_SPACES EOL CONFIG SETUP CONN INCLUDE VERSION
%token <s>      STRING
%token <num>    INTEGER
%token <num>    BOOL
%token <k>      KEYWORD
%token <k>      TIMEWORD
%token <k>      BOOLWORD
%token <k>      PERCENTWORD
%token <k>      COMMENT
%%

/*
 * Config file
 */

config_file:
        blanklines versionstmt blanklines sections
        | blanklines sections
        ;

/* check out the version number - this is optional (and we're phasing out its use) */
/* we have configs shipped with version 2 (INTEGER) and with version 2.0 (STRING, now  NUMBER/float was removed */

versionstmt:
        | VERSION STRING EOL
        | VERSION INTEGER EOL
	;

blanklines: /* NULL */
	| blanklines EOL
	| blanklines FIRST_SPACES EOL
	;

sections: /* NULL */
	| sections section_or_include
	;

section_or_include:
	CONFIG SETUP EOL {
		_parser_kw = &(_parser_cfg->config_setup);
		_parser_kw_last = NULL;
		_parser_comments = &_parser_cfg->comments;
		if(yydebug) fprintf(stderr, "\nconfig setup read\n");

	} kw_sections
	| CONN STRING EOL {
		struct section_list *section;
		section = (struct section_list *)malloc(sizeof(struct section_list));
		if (section) {

			section->name = $2;
			section->kw = NULL;

			TAILQ_INSERT_TAIL(&_parser_cfg->sections, section, link);

        	        /* setup keyword section to record values */
			_parser_kw = &(section->kw);
			_parser_kw_last = NULL;

			/* and comments */
			TAILQ_INIT(&section->comments);
			_parser_comments = &section->comments;

			if(yydebug) fprintf(stderr, "\nread conn %s\n", section->name);

		}
		else {
			_parser_kw = NULL;
			_parser_kw_last = NULL;
			yyerror("can't allocate memory in section_or_include/conn");
		}
	} kw_sections
	| INCLUDE STRING EOL {
 		parser_y_include($2);
	}
	;

kw_sections:
	kw_sections kw_section
	| /* NULL */
	;

kw_section: FIRST_SPACES statement_kw EOL ;

statement_kw:
	KEYWORD EQUAL KEYWORD {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (!new) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    struct keyword kw;
                    /* because the third argument was also a keyword, we dig up the string representation. */
	            const char *value = $3.keydef->keyname;

	            kw = $1;

                    process_keyword_equal(kw, new, value);
		    new->next = NULL;

		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
	}
	| COMMENT EQUAL STRING {
		struct starter_comments *new;

		new = alloc_comment();
		if (new) {
		    new->x_comment = strdup($1.string);
		    new->commentvalue = strdup($3);
	            TAILQ_INSERT_TAIL(_parser_comments, new, link);
                }
		else {
		    yyerror("can't allocate memory in statement_kw");
		}
	}
	| KEYWORD EQUAL STRING {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (!new) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    struct keyword kw;

	            kw = $1;
                    process_keyword_equal(kw, new, $3);
		    new->next = NULL;

		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
	}

	| BOOLWORD EQUAL BOOL {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new) {
		    new->keyword = $1;
		    new->number = $<num>3;  /* Should not be necessary! */
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
		else {
		    yyerror("can't allocate memory in statement_kw");
		}
	}
	| KEYWORD EQUAL INTEGER {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new) {
		    new->keyword = $1;
		    new->number = $<num>3;  /* Should not be necessary! */
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
		else {
		    yyerror("can't allocate memory in statement_kw");
		}
	}
	| TIMEWORD EQUAL STRING {
		struct kw_list *new;
		char *endptr, *str;
                unsigned int val;
		struct keyword kw = $1;
		bool fail;
                char buf[80];


		fail = FALSE;

		str = $3;

		val = strtoul(str, &endptr, 10);

		if(endptr == str) {
                  snprintf(buf, 80, "bad duration value %s=%s", kw.keydef->keyname, str);
                  yyerror(buf);
		  fail = TRUE;

		}

		if(!fail)
                {
		  if(*endptr == '\0') { /* nothing */ }
		  else if ((*endptr == 's') && (endptr[1] == '\0')) { }
		  else if ((*endptr == 'm') && (endptr[1] == '\0')) { val *= 60; }
		  else if ((*endptr == 'h') && (endptr[1] == '\0')) { val *= 3600; }
		  else if ((*endptr == 'd') && (endptr[1] == '\0')) { val *= 3600*24; }
		  else if ((*endptr == 'w') && (endptr[1] == '\0')) { val *= 7*3600*24; }
		  else {
                    snprintf(buf, 80, "bad duration multiplier '%c' on %s", *endptr, str);
                    yyerror(buf);
                    fail=TRUE;
                  }
                }

	        if(!fail)
                {
		  assert(_parser_kw != NULL);
		  new = alloc_kwlist();
		  if (new) {
		    new->keyword = $1;
		    new->number = val;
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		  }
		  else {
		    yyerror("can't allocate memory in statement_kw");
		  }
                }
	}
	| PERCENTWORD EQUAL STRING {
		struct kw_list *new;
		char *endptr, *str;
		struct keyword kw = $1;
                unsigned int val;
		bool fail;
                char buf[80];


		fail = FALSE;

		str = $3;

		val = strtoul(str, &endptr, 10);

		if(endptr == str) {
                  snprintf(buf, 80, "bad percent value %s=%s", kw.keydef->keyname, str);
                  yyerror(buf);
		  fail = TRUE;

		}

		if(!fail)
                {
		  if ((*endptr == '%') && (endptr[1] == '\0')) { }
		  else {
                    snprintf(buf, 80, "bad percentage multiplier '%c' on %s", *endptr, str);
                    yyerror(buf);
                    fail=TRUE;
                  }
                }

	        if(!fail)
                {
		  assert(_parser_kw != NULL);
		  new = alloc_kwlist();
		  if (new) {
		    new->keyword = $1;
		    new->number = val;
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		  }
		  else {
		    yyerror("can't allocate memory in statement_kw");
		  }
                }
	}
	| KEYWORD EQUAL BOOL {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new) {
		    new->keyword = $1;
		    new->number = $<num>3;  /* Should not be necessary! */
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
		else {
		    yyerror("can't allocate memory in statement_kw");
		}
	}
	| KEYWORD EQUAL { /* this is meaningless, we ignore it */ }
	;

%%

void yyerror(const char *s)
{
	extern void parser_y_error(char *b, int size, const char *sp);
	if (_save_errors_)
		parser_y_error(parser_errstring, ERRSTRING_LEN, s);
}

struct config_parsed *parser_load_conf (const char *file, err_t *perr)
{
	struct config_parsed *cfg=NULL;
	int err = 0;
	FILE *f;

	extern FILE *yyin;

	memset(parser_errstring, 0, ERRSTRING_LEN+1);
	if (perr) *perr = NULL;

	cfg = (struct config_parsed *)malloc(sizeof(struct config_parsed));
	if (cfg) {
		memset(cfg, 0, sizeof(struct config_parsed));
		if (strncmp(file, "-", sizeof("-")) == 0) {
			f = fdopen(STDIN_FILENO, "r");
		}
		else {
			f = fopen(file, "r");
		}
		if (f) {
			yyin = f;
			parser_y_init(file, f);
			_save_errors_=1;
			TAILQ_INIT(&cfg->sections);
			TAILQ_INIT(&cfg->comments);
			_parser_cfg = cfg;

	   	        if (yyparse()!=0) {
				if (parser_errstring[0]=='\0') {
					snprintf(parser_errstring, ERRSTRING_LEN,
						"Unknown error...");
				}
				_save_errors_=0;
				while (yyparse()!=0);
				err++;
			}
			else if (parser_errstring[0]!='\0') {
				err++;
			}
			else {
				/**
				 * Config valid
				 */
			}
		}
		else {
			snprintf(parser_errstring, ERRSTRING_LEN, "can't load file '%s'",
				file);
			err++;
		}
	}
	else {
		snprintf(parser_errstring, ERRSTRING_LEN, "can't allocate memory");
		err++;
	}

	if (err) {
		if (perr) *perr = (err_t)strdup(parser_errstring);
		if (cfg) parser_free_conf (cfg);
		cfg = NULL;
	}

	return cfg;
}

static void parser_free_kwlist (struct kw_list *list)
{
	struct kw_list *elt;
	while (list) {
		elt = list;
		list = list->next;
		if (elt->keyword.string)   free(elt->keyword.string);
		if (elt->argument) free(elt->argument);
		free(elt);
	}
}

void parser_free_conf (struct config_parsed *cfg)
{
	struct section_list *seci, *sec;
	if (cfg) {
		parser_free_kwlist(cfg->config_setup);

	        for(seci = cfg->sections.tqh_first; seci != NULL; )
		{
			sec = seci;
			seci = seci->link.tqe_next;

			if (sec->name) free(sec->name);
			parser_free_kwlist(sec->kw);
			free(sec);
		}

		free(cfg);
	}
}

struct kw_list *alloc_kwlist(void)
{
	struct kw_list *new;

	new = (struct kw_list *)malloc(sizeof(struct kw_list));
	memset(new, 0, sizeof(struct kw_list));
	return new;
}

struct starter_comments *alloc_comment(void)
{
	struct starter_comments *new;

	new = (struct starter_comments *)malloc(sizeof(struct starter_comments));
	memset(new, 0, sizeof(struct starter_comments));
	return new;
}

void process_keyword_equal(struct keyword kw, struct kw_list *new, const char *const_string)
{
    /* copy the string, as we may want to smash it around a bit */
    char *string = alloca(strlen(const_string)+1);
    char *rest = NULL;

    strcpy(string, const_string);

    new->keyword = kw;
    switch(kw.keydef->type) {
    case kt_list:
        new->number = parser_enum_list(kw.keydef, string, TRUE);
        break;
    case kt_enum:
        new->number = parser_enum_list(kw.keydef, string, FALSE);
        break;
    case kt_rsakey:
    case kt_loose_enum:
        new->number = parser_loose_enum(&new->keyword, string);
        break;
    case kt_loose_enumarg:
        new->number = parser_loose_enum_arg(&new->keyword, string, &rest);
        if(rest) {
            new->argument=strdup(rest);
        }
        break;
    case kt_string:
    case kt_appendstring:
    case kt_appendlist:
    case kt_filename:
    case kt_dirname:
    case kt_ipaddr:
    case kt_bitstring:
    case kt_idtype:
    case kt_subnet:
        new->keyword.string = strdup(string);
        break;

    case kt_bool:
    case kt_invertbool:
    case kt_number:
    case kt_time:
    case kt_percent:
        yyerror("valid keyword, but value is not a number");
        assert(!(kw.keydef->type == kt_bool));
        break;
    case kt_comment:
        break;
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
