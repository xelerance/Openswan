/* lexer (lexical analyzer) for control files
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
#ifndef _LEX_H
#define _LEX_H

struct file_lex_position
{
    int depth;	/* how deeply we are nested */
    const char *root_dir;
    const char *filename;
    FILE *fp;
    enum { B_none, B_record, B_file } bdry;	/* current boundary */
    int lino;	/* line number in file */
    char    *tok_buffer;
    size_t   tok_buflen;
    char *cur;	/* cursor */
    char under;	/* except in shift(): character orignally at *cur */
    char *tok;
    struct file_lex_position *previous;
};

extern struct file_lex_position *flp;

extern bool lexopen(struct file_lex_position *new_flp, const char *name, bool optional);
extern void lexclose(void);

#define tokeq(s) (streq(flp->tok, (s)))
#define tokeqword(s) (strcasecmp(flp->tok, (s)) == 0)

extern bool shift(void);
extern bool flushline(const char *m);

#endif /* _LEX_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
