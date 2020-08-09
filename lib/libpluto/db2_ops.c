/*
 * Dynamic db (proposal, transforms, attributes) handling for IKEv2.
 * based upon db_ops.c by: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2017: Michael Richardson <mcr@xelerance.com>
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

/*
 * The stratedy is to have (full contained) struct db_prop in db_context
 * pointing to ONE dynamically sizable transform vector (trans0).
 * Each transform stores attrib. in ONE dyn. sizable attribute vector (attrs0)
 * in a "serialized" way (attributes storage is used in linear sequence for
 * subsecuent transforms).
 *
 * Resizing for both trans0 and attrs0 is supported:
 * - For conj0:  quite simple, just allocate and copy trans. vector content
 *               also update conj_cur (by offset)
 * - For trans0: quite simple, just allocate and copy trans. vector content
 *               also update trans_cur (by offset), but also must move
 *               all the attributes upwards.
 * - For attrs0: after allocating and copying attrs, I must rewrite each
 *               trans->attrs present in trans0; to achieve this, calculate
 *               attrs pointer offset (new minus old) and iterate over
 *               each transform "adding" this difference.
 *               also update attrs_cur (by offset)
 *
 * db_context structure:
 * 	+---------------------+
 *	|  prop               |
 *	|    .conj            | --+
 *	|    .conj_cnt        |   |
 *	+---------------------+ <-+
 *	|  conj0              | ----> { conj#1 | ... | conj#i | ...   }
 *	|    .protoid         |
 *	+---------------------+                       ^
 *	|  conj_cur           | ----------------------' current conj.
 *	+---------------------+ <-+
 *	|  trans0             | ----> { trans#1 | ... | trans#i | ...   }
 *	+---------------------+                       ^
 *	|  trans_cur          | ----------------------' current transf.
 *	+---------------------+
 *	|  attrs0             | ----> { attr#1 | ... | attr#j | ...  }
 *	+---------------------+                      ^
 *	|  attrs_cur          | ---------------------' current attr.
 *	+---------------------+
 *	| max_trans,max_attrs |  max_trans/attrs: number of elem. of each vector
 *	+---------------------+
 *
 * See testing examples at end for interface usage.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stddef.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "pluto/defs.h"
#include "packet.h"
#include "pluto/db2_ops.h"
#include "pluto/db_ops.h"
#include "oswlog.h"

#include <assert.h>

/*	Initialize db object
 *	max_trans and max_attrs can be 0, will be dynamically expanded
 *	as a result of "add" operations
 */
int
db2_prop_init(struct db_v2_context *ctx
              , int max_conj
              , int max_trans
              , int max_attrs)
{
  if (ctx == NULL)
    goto err_input;

  db2_destroy(ctx);  /* free up any conj0/trans0/attrs0 from before */

  if (max_conj <= 0)
    goto err_input;
  if (max_trans <= 0)
    goto err_input;
  if (max_attrs <= 0)
    goto err_input;

  ctx->conj0 = alloc_bytes(sizeof(struct db_v2_prop_conj)*max_conj,
                           "db_context->conj");
  if (!ctx->conj0)
    goto err_alloc;

  ctx->trans0 = alloc_bytes(sizeof(struct db_v2_trans)*max_trans,
                            "db_context->trans");
  if (!ctx->trans0)
    goto err_alloc;

  ctx->attrs0 = alloc_bytes(sizeof (struct db_v2_attr) * max_attrs,
                            "db_context->attrs");
  if (!ctx->attrs0)
    goto err_alloc;

  ctx->max_trans = max_trans;
  ctx->max_attrs = max_attrs;
  ctx->max_conj  = max_conj;
  ctx->trans_cur = ctx->trans0;
  ctx->attrs_cur = ctx->attrs0;
  ctx->conj_cur  = ctx->conj0;
  ctx->prop.props = ctx->conj0;
  ctx->prop.prop_cnt = 0;
  ctx->prop.conjnum   = 1;
  return 0;

err_alloc:
  db2_destroy(ctx);
err_input:
  return -1;
}

struct db_v2_context *db2_prop_new(int max_conj
                                 , int max_trans
                                 , int max_attrs)
{
  struct db_v2_context *new_db2;
  new_db2 = alloc_bytes(sizeof(struct db_v2_context),
                        "db_context");

  if(new_db2 && db2_prop_init(new_db2, max_conj, max_trans, max_attrs) < 0) {
    if(new_db2) pfree(new_db2);
    return NULL;
  }
  return new_db2;
}

/*	Clear out a db object */
void
db2_destroy(struct db_v2_context *ctx)
{
  if(ctx == NULL) return;
  if (ctx->conj0)  pfree(ctx->conj0);
  if (ctx->trans0) pfree(ctx->trans0);
  if (ctx->attrs0) pfree(ctx->attrs0);
  ctx->conj0  = NULL;
  ctx->trans0 = NULL;
  ctx->attrs0 = NULL;
}

/*	Free a db object itself, and things contained in it */
void
db2_free(struct db_v2_context *ctx)
{
  db2_destroy(ctx);
  pfree(ctx);
}

/*	Expand storage for transforms by number delta_trans */
static int
db2_prop_expand(struct db_v2_context *ctx, int delta_conj)
{
  /*	Start a new proposal, expand conj0 is needed */
  int ret = -1;
  struct db_v2_prop_conj *new_conj, *old_conj;
  int max_conj = ctx->max_conj + delta_conj;
  ptrdiff_t offset;

  old_conj = ctx->conj0;
  new_conj = alloc_bytes( sizeof (struct db_v2_prop_conj) * max_conj,
                          "db_context->conj (expand)");
  //DBG_log("expanding[%u] conj0 %p -> %p [%u]", delta_conj, old_conj, new_conj, max_conj);
  if (!new_conj)
    goto out;
  memcpy(new_conj, old_conj, ctx->max_conj * sizeof(struct db_v2_prop_conj));

  /* update conj0 (obviously) */
  ctx->conj0 = ctx->prop.props = new_conj;

  /* update conj_cur (by offset) */
  offset = (char *)(new_conj) - (char *)(old_conj);
  {
    char *cctx = (char *)(ctx->conj_cur);

    cctx += offset;
    ctx->conj_cur = (struct db_v2_prop_conj *)cctx;
  }

  /* update elem count */
  ctx->max_conj = max_conj;
  if(old_conj) {
    pfree(old_conj);
  }
  ret = 0;
out:
  return ret;
}

/*	Find space for a new transform */
static void
db2_trans_increment(struct db_v2_context *ctx)
{
  /*	skip incrementing current trans pointer the 1st time*/
  if (ctx->trans_cur && ctx->trans_cur->transform_type)
    ctx->trans_cur++;
}

int
db2_prop_add(struct db_v2_context *ctx, u_int8_t protoid, u_int8_t spisize)
{
  /*	skip incrementing current conj pointer the 1st time*/
  if (ctx->conj_cur && ctx->conj_cur->trans_cnt)
    ctx->conj_cur++;

  /*
   *	Strategy: if more space is needed, expand by
   *	          <current_size>/2 + 1
   */
  if ((ctx->conj_cur - ctx->conj0) >= ctx->max_conj) {
    if (db2_prop_expand(ctx, ctx->max_conj/2 + 1)<0)
      return -1;
  }

  ctx->conj_cur->propnum = ctx->prop.conjnum;
  ctx->conj_cur->protoid = protoid;
  ctx->conj_cur->spisize = spisize;

  /* bump to next available transforms, if neccessary */
  db2_trans_increment(ctx);
  ctx->conj_cur->trans   = ctx->trans_cur;
  ctx->conj_cur->trans_cnt = 0;
  ctx->prop.prop_cnt++;
  return 0;
}

/*	Expand storage for transforms by number delta_trans */
static int
db2_trans_expand(struct db_v2_context *ctx, int delta_trans)
{
  int ret = -1;
  struct db_v2_trans *new_trans, *old_trans;
  int max_trans = ctx->max_trans + delta_trans;
  ptrdiff_t offset;
  struct db_v2_prop_conj *pc;
  int                     pi;

  old_trans = ctx->trans0;
  new_trans = alloc_bytes( sizeof (struct db_v2_trans) * max_trans,
                           "db_context->trans (expand)");
  if (!new_trans)
    goto out;
  memcpy(new_trans, old_trans, ctx->max_trans * sizeof(struct db_v2_trans));

  /* update trans0 (obviously) */
  ctx->trans0 = new_trans;

  /* update trans_cur (by offset) */
  offset = (char *)(new_trans) - (char *)(old_trans);

  {
    char *cctx = (char *)(ctx->trans_cur);

    cctx += offset;
    ctx->trans_cur = (struct db_v2_trans *)cctx;
  }

  /* now walk through all the prop_conj, and adjust the pointer */
  for (pc=ctx->prop.props, pi=0; pi < ctx->prop.prop_cnt; pc++, pi++) {
    char *transx = (char *)(pc->trans);
    transx += offset;
    pc->trans = (struct db_v2_trans *)transx;
  }

  /* update elem count */
  ctx->max_trans = max_trans;
  if(old_trans) {
    pfree(old_trans);
  }
  ret = 0;
 out:
  return ret;
}

/*	Start a new transform, expand trans0 is needed */
int
db2_trans_add(struct db_v2_context *ctx, u_int8_t transid, u_int8_t value)
{
  db2_trans_increment(ctx);

  /*
   *	Strategy: if more space is needed, expand by
   *	          <current_size>/2 + 1
   *
   *	This happens to produce a "reasonable" sequence
   *	after few allocations, eg.:
   *	0,1,2,4,8,13,20,31,47
   */
  passert(ctx->trans_cur != NULL);
  if ((ctx->trans_cur - ctx->trans0) >= (ctx->max_trans-1)) {
    if (db2_trans_expand(ctx, ctx->max_trans/2 + 1)<0)
      return -1;
  }

  ctx->trans_cur->transform_type = transid;
  ctx->trans_cur->value          = value;
  ctx->trans_cur->attrs   = ctx->attrs_cur;
  ctx->trans_cur->attr_cnt = 0;
  ctx->conj_cur->trans_cnt++;
  return 0;
}

/*
 *	Expand storage for attributes by delta_attrs number AND
 *	rewrite trans->attr pointers
 */
static int
db2_attrs_expand(struct db_v2_context *ctx, int delta_attrs)
{
  int ret = -1;
  struct db_v2_attr *new_attrs, *old_attrs;
  struct db_v2_trans *t;
  int max_attrs = ctx->max_attrs + delta_attrs;
  ptrdiff_t offset;

  old_attrs = ctx->attrs0;
  new_attrs = alloc_bytes( sizeof (struct db_v2_attr) * max_attrs,
                           "db2_expand->attrs");
  if (!new_attrs)
    goto out;

  memcpy(new_attrs, old_attrs, ctx->max_attrs * sizeof(struct db_attr));

  /* update attrs0 and attrs_cur (obviously) */
  offset = (char *)(new_attrs) - (char *)(old_attrs);

  {
    char *actx = (char *)(ctx->attrs0);

    actx += offset;
    ctx->attrs0 = (struct db_v2_attr *)actx;

    actx = (char *)ctx->attrs_cur;
    actx += offset;
    ctx->attrs_cur = (struct db_v2_attr *)actx;
  }

  /* for each transform, rewrite attrs pointer by offsetting it */
  for (t=ctx->trans0; t <= ctx->trans_cur; t++) {
    {
      char *actx = (char *)(t->attrs);

      actx += offset;
      t->attrs = (struct db_v2_attr *)actx;
    }
  }

  /* update elem count */
  ctx->max_attrs = max_attrs;
  if(old_attrs) pfree(old_attrs);
  ret = 0;
 out:
  return ret;
}

/*	Add attr copy to current transform, expanding attrs0 if needed */
int
db2_attr_add(struct db_v2_context *ctx, u_int16_t type, u_int16_t val)
{
  /*
   *	Strategy: if more space is needed, expand by
   *	          <current_size>/2 + 1
   */
  if ((ctx->attrs_cur - ctx->attrs0) >= ctx->max_attrs) {
    if (db2_attrs_expand(ctx, ctx->max_attrs/2 + 1) < 0)
      return -1;
  }
  ctx->attrs_cur->ikev2 = type;
  ctx->attrs_cur->val   = val;
  ctx->attrs_cur++;
  ctx->trans_cur->attr_cnt++;
  return 0;
}

/*	Start a new proposal, an alternative to current one */
void db2_prop_close(struct db_v2_context *ctx)
{
  ctx->prop.conjnum++;
}

/*
 * From below to end just testing stuff ....
 */
static void db2_prop_print(struct db_v2_prop_conj *p)
{
  struct db_v2_trans *t;
  struct db_v2_attr *a;
  int ti, ai;
  enum_names *n;

  DBG_log("%u:  protoid=\"%s\" [trans: %u]"
          , p->propnum
          , enum_name(&protocol_names, p->protoid)
          , p->trans_cnt);
  for (ti=0, t=p->trans; ti< p->trans_cnt; ti++, t++) {
    if(t->transform_type < ikev2_transid_val_descs_size) {
      n = ikev2_transid_val_descs[t->transform_type];
    } else {
      continue;
    }
    DBG_log("    %s value=\"%s\" [attrs: %u]"
            , enum_name(&trans_type_names, t->transform_type)
            , enum_name(n, t->value)
            , t->attr_cnt);
    for (ai=0, a=t->attrs; ai < t->attr_cnt; ai++, a++) {
      DBG_log("      type=\"%s\" value=\"%u\"",
              enum_name(&ikev2_trans_attr_descs, a->ikev2),
              a->val);
    }
  }

}

void db2_print(struct db_v2_context *ctx)
{
  int i;
  if(ctx == NULL) return;
  DBG_log("proposals: cnt=%u (next=%u)",
          ctx->prop.prop_cnt, ctx->prop.conjnum);

  for(i=0; i < ctx->prop.prop_cnt; i++) {
    db2_prop_print(&ctx->prop.props[i]);
  }
}

/*
 * From below to end just testing stuff ....
 */
static void db2_propj_print(struct db_v2_prop *pj)
{
  int i;

  DBG_log(" disj: cnt=%u [next=%u]", pj->prop_cnt, pj->conjnum);
  for(i=0; i < pj->prop_cnt; i++) {
    db2_prop_print(&pj->props[i]);
  }
}

void sa_v2_print(struct db_sa *sa)
{
  int i;
  if(sa == NULL) return;
  DBG_log("proposals: cnt=%u",
          sa->prop_disj_cnt);

  for(i=0; i < sa->prop_disj_cnt; i++) {
    db2_propj_print(&sa->prop_disj[i]);
  }
}

static void
free_sa_v2_trans(struct db_v2_trans *tr)
{
  if(tr->attrs) {
    pfree(tr->attrs);
    tr->attrs=NULL;
  }
}

static void
free_sa_v2_prop(struct db_v2_prop_conj *dp)
{
    unsigned int i;
    for(i=0; i<dp->trans_cnt; i++) {
	free_sa_v2_trans(&dp->trans[i]);
    }
    if(dp->trans) {
	pfree(dp->trans);
	dp->trans=NULL;
    }
}

static void
free_sa_v2_prop_disj(struct db_v2_prop *pc)
{
    unsigned int i;
    for(i=0; i<pc->prop_cnt; i++) {
	free_sa_v2_prop(&pc->props[i]);
    }
    if(pc->props) {
	pfree(pc->props);
        pc->props = NULL;
    }
}

void free_sa(struct db_sa *f)
{
    unsigned int i;
    if(f == NULL) return;

    if(f->prop_v1_ctx) {
        db_destroy(f->prop_v1_ctx);
        f->prop_v1_ctx = NULL;
    }

    if(f->prop_conjs) {
	pfree(f->prop_conjs);
	f->prop_conjs=NULL;
	f->prop_conj_cnt=0;
    }

    /*
     * if prop_ctx is non-null, then all the prop/prop_conj/attrs
     * were allocated within it, and we can just free block.
     */
    if(f->prop_ctx) {
        db2_free(f->prop_ctx);
        f->prop_ctx = NULL;
        f->prop_disj= NULL;
        f->prop_disj_cnt=0;
    } else {
      /* else, they were allocated individually */
      for(i=0; i<f->prop_disj_cnt; i++) {
        free_sa_v2_prop_disj(&f->prop_disj[i]);
      }
      if(f->prop_disj) {
        pfree(f->prop_disj);
        f->prop_disj=NULL;
        f->prop_disj_cnt=0;
      }
    }

    pfree(f);
}

void clone_trans(struct db_trans *tr)
{
    tr->attrs = clone_bytes(tr->attrs
			    , tr->attr_cnt*sizeof(tr->attrs[0])
			    , "sa copy attrs array");
}

void clone_prop(struct db_prop *p, int extra)
{
    unsigned int i;

    p->trans = clone_bytes(p->trans
			  , (p->trans_cnt+extra)*sizeof(p->trans[0])
			  , "sa copy trans array");
    for(i=0; i<p->trans_cnt; i++) {
	clone_trans(&p->trans[i]);
    }
}

void clone_propconj(struct db_prop_conj *pc, int extra)
{
    unsigned int i;

    pc->props = clone_bytes(pc->props
			   , (pc->prop_cnt+extra)*sizeof(pc->props[0])
			   , "sa copy prop array");
    for(i=0; i<pc->prop_cnt; i++) {
	clone_prop(&pc->props[i], 0);
    }
}

struct db_sa *sa_copy_sa(struct db_sa *sa, int extra)
{
    unsigned int i;
    struct db_sa *nsa;

    nsa = clone_thing(*sa, "sa copy prop_conj");
    nsa->parentSA= sa->parentSA;

    nsa->prop_conjs =
	clone_bytes(nsa->prop_conjs
		    , (nsa->prop_conj_cnt+extra)*sizeof(nsa->prop_conjs[0])
		    , "sa copy prop conj array");

    for(i=0; i<nsa->prop_conj_cnt; i++) {
	clone_propconj(&nsa->prop_conjs[i], 0);
    }

    return nsa;
}

/*
 * clone the sa, but keep only the first proposal
 */
struct db_sa *sa_copy_sa_first(struct db_sa *sa)
{
    struct db_sa *nsa;
    struct db_prop_conj *pc;
    struct db_prop *p;

    nsa = clone_thing(*sa, "sa copy prop_conj");
    if(nsa->prop_conj_cnt == 0) {
      return nsa;
    }
    nsa->prop_conj_cnt = 1;
    nsa->prop_conjs = clone_bytes(nsa->prop_conjs
				  , sizeof(nsa->prop_conjs[0])
				  , "sa copy 1 prop conj array");

    pc = &nsa->prop_conjs[0];
    if(pc->prop_cnt == 0) {
      return nsa;
    }
    pc->prop_cnt = 1;
    pc->props = clone_bytes(pc->props
			    , sizeof(pc->props[0])
			    , "sa copy 1 prop array");

    p = &pc->props[0];
    if(p->trans_cnt == 0) {
      return nsa;
    }
    p->trans_cnt = 1;
    p->trans = clone_bytes(p->trans
			   , sizeof(p->trans[0])
			   , "sa copy 1 trans array");

    clone_trans(&p->trans[0]);
    return nsa;
}

/*
 * this routine takes two proposals and conjoins them (or)
 *
 *
 */
struct db_sa *
sa_merge_proposals(struct db_sa *a, struct db_sa *b)
{
    struct db_sa *n;
    unsigned int i,j,k;

    if(a == NULL || a->prop_conj_cnt == 0) {
	return sa_copy_sa(b, 0);
    }
    if(b == NULL || b->prop_conj_cnt == 0) {
	return sa_copy_sa(a, 0);
    }

    n = clone_thing(*a, "conjoin sa");

    passert(a->prop_conj_cnt == b->prop_conj_cnt);
    passert(a->prop_conj_cnt == 1);

    n->prop_conjs =
	clone_bytes(n->prop_conjs
		    , n->prop_conj_cnt*sizeof(n->prop_conjs[0])
		    , "sa copy prop conj array");

    for(i=0; i<n->prop_conj_cnt; i++) {
	struct db_prop_conj *pca= &n->prop_conjs[i];
	struct db_prop_conj *pcb= &b->prop_conjs[i];

	passert(pca->prop_cnt == pcb->prop_cnt);
	passert(pca->prop_cnt == 1);

	pca->props = clone_bytes(pca->props
				, pca->prop_cnt*sizeof(pca->props[0])
				, "sa copy prop array");

	for(j=0; j<pca->prop_cnt; j++) {
	    struct db_prop *pa = &pca->props[j];
	    struct db_prop *pb = &pcb->props[j];
	    struct db_trans *t;
	    int t_cnt = (pa->trans_cnt+pb->trans_cnt);

	    t = alloc_bytes(t_cnt*sizeof(pa->trans[0])
			    , "sa copy trans array");

	    memcpy(t, pa->trans, (pa->trans_cnt)*sizeof(pa->trans[0]));
	    memcpy(t+(pa->trans_cnt)
		   , pb->trans
		   , (pb->trans_cnt)*sizeof(pa->trans[0]));

	    pa->trans = t;
	    pa->trans_cnt = t_cnt;
	    for(k=0; k<pa->trans_cnt; k++) {
		clone_trans(&pa->trans[k]);
	    }
	}
    }

    n->parentSA = a->parentSA;
    return n;
}
