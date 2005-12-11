/* A Bison parser, made by GNU Bison 1.875d.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     EQUAL = 258,
     FIRST_SPACES = 259,
     EOL = 260,
     CONFIG = 261,
     SETUP = 262,
     CONN = 263,
     INCLUDE = 264,
     VERSION = 265,
     DEFAULT = 266,
     TIMEWORD = 267,
     NUMBER = 268,
     STRING = 269,
     INTEGER = 270,
     BOOL = 271,
     KEYWORD = 272,
     BOOLWORD = 273,
     PERCENTWORD = 274
   };
#endif
#define EQUAL 258
#define FIRST_SPACES 259
#define EOL 260
#define CONFIG 261
#define SETUP 262
#define CONN 263
#define INCLUDE 264
#define VERSION 265
#define DEFAULT 266
#define TIMEWORD 267
#define NUMBER 268
#define STRING 269
#define INTEGER 270
#define BOOL 271
#define KEYWORD 272
#define BOOLWORD 273
#define PERCENTWORD 274




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 52 "parser.y"
typedef union YYSTYPE {
	char *s;
        unsigned int num;
	double dblnum;
	struct keyword k;
} YYSTYPE;
/* Line 1285 of yacc.c.  */
#line 82 "parser.tab.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



