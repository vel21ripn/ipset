/*
 * ahocorasick.c: implementation of ahocorasick library's functions
 * This file is part of multifast.
 *
 Copyright 2010-2012 Kamiar Kanani <kamiar.kanani@gmail.com>

 multifast is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 multifast is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with multifast.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#else
#include <asm/byteorder.h>
#include <linux/kernel.h>
#include <linux/types.h>
typedef __kernel_size_t size_t;
#include <linux/string.h>
#include <linux/slab.h>
#endif

#include "libahocorasick.h"

/* TODO: For different depth of node, number of outgoing edges differs
   considerably, It is efficient to use different chunk size for 
   different depths */

/* Private function prototype */
static int  node_edge_compare (struct edge * e, int a, int b);
static int  node_has_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * newstr);

static AC_NODE_t * node_create            (void);
static AC_NODE_t * node_create_next       (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
static int         node_register_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * str);
static int         node_register_outgoing (AC_NODE_t * thiz, AC_NODE_t * next, AC_ALPHABET_t alpha);
static AC_NODE_t * node_find_next         (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
static AC_NODE_t * node_findbs_next       (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
static void        node_release           (AC_NODE_t * thiz);
static inline void node_sort_edges        (AC_NODE_t * thiz);

#ifndef __KERNEL__
static void dump_node_header(AC_NODE_t * n,size_t *);
#endif

/* Private function prototype */
static int ac_automata_union_matchstrs (AC_NODE_t * node);
static void ac_automata_set_failure
		(AC_AUTOMATA_t * thiz, AC_NODE_t * node, struct ac_path * path);
static void ac_automata_traverse_setfailure
		(AC_AUTOMATA_t * thiz);

#ifdef __KERNEL__
static inline void *acho_calloc(size_t nmemb, size_t size) {
	return kcalloc(nmemb, size, GFP_ATOMIC);
}
static inline void *acho_malloc(size_t size) {
	return kmalloc(size, GFP_ATOMIC);
}
static inline void acho_free(void *old) {
	return kfree(old);
}
#else
void *acho_calloc(size_t nmemb, size_t size);
void *acho_malloc(size_t size);
void acho_free(void *old);
#endif

static void acho_sort(struct edge *e, size_t num,
      int (*cmp_func)(struct edge *e, int a, int b),
      void (*swap_func)(struct edge *e, int a, int b));


/******************************************************************************
 * FUNCTION: ac_automata_init
 * Initialize automata; allocate memories and set initial values
 * PARAMS:
 * MATCH_CALLBACK mc: call-back function
 * the call-back function will be used to reach the caller on match occurrence
 ******************************************************************************/
AC_AUTOMATA_t * ac_automata_init (void)
{
  AC_AUTOMATA_t * thiz = (AC_AUTOMATA_t *)acho_calloc(1,sizeof(AC_AUTOMATA_t));
  if(!thiz) return NULL;
  thiz->root = node_create ();
  if(!thiz->root) {
	  acho_free(thiz);
	  return NULL;
  }

  thiz->total_patterns = 0;
  thiz->automata_open = 1;
  return thiz;
}

/******************************************************************************
 * FUNCTION: ac_automata_add
 * Adds pattern to the automata.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * AC_PATTERN_t * patt: the pointer to added pattern
 * RETUERN VALUE: AC_ERROR_t
 * the return value indicates the success or failure of adding action
 ******************************************************************************/
AC_ERROR_t ac_automata_add (AC_AUTOMATA_t * thiz, AC_PATTERN_t * patt)
{
  unsigned int i;
  AC_NODE_t * n = thiz->root;
  AC_NODE_t * next;
  AC_ALPHABET_t alpha;

  if(!thiz->automata_open)
    return ACERR_AUTOMATA_CLOSED;

  if (!patt->length)
    return ACERR_ZERO_PATTERN;

  if (patt->length > AC_PATTRN_MAX_LENGTH)
    return ACERR_LONG_PATTERN;

  for (i=0; i<patt->length; i++)
    {
      alpha = patt->astring[i];
      if ((next = node_find_next(n, alpha)))
	{
	  n = next;
	  continue;
	}
      else
	{
	  next = node_create_next(n, alpha);
	  if(!next)
		  return ACERR_ERROR;
	  next->id = ++thiz->id;
	  thiz->all_nodes_num++;
	  n = next;
	}
    }
  if(thiz->max_str_len < patt->length)
     thiz->max_str_len = patt->length;

  if(n->final) {
    patt->rep.number = n->matched_patterns->patterns[0].rep.number;
    return ACERR_DUPLICATE_PATTERN;
  }

  n->final = 1;
 
  if(node_register_matchstr(n, patt))
	  return ACERR_ERROR;
 
  thiz->total_patterns++;

  return ACERR_SUCCESS;
}

static void node_outgoing_bitmap(AC_NODE_t * n)
{
  int i;
  struct edge *e;
  AC_ALPHABET_t *c;

  if(!n->use || n->one || !n->outgoing) return;

  e = n->outgoing;
  memset((char *)&e->cmap,0,sizeof(e->cmap));
  c = edge_get_alpha(e);
  for (i=0; i < e->degree; i++)
      e->cmap[(unsigned char)c[i] >> 5] |= 1 << (c[i] & 0x1f);
}

/******************************************************************************
 * FUNCTION: ac_automata_finalize
 * Locate the failure node for all nodes and collect all matched pattern for
 * every node. it also sorts outgoing edges of node, so binary search could be
 * performed on them. after calling this function the automate literally will
 * be finalized and you can not add new patterns to the automate.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 ******************************************************************************/
AC_ERROR_t ac_automata_finalize (AC_AUTOMATA_t * thiz)
{
  unsigned int ip, i, node_id = 0;
  AC_NODE_t * n, *next;
  struct ac_path *path;

  path  = thiz->ac_path;

  ac_automata_traverse_setfailure (thiz);

  path[1].n = thiz->root;
  path[1].idx = 0;
  ip = 1;

  while(ip != 0) {

        n = path[ip].n;
		if(!n->ff) {
			n->id = ++node_id;
			n->ff = 1;
			if(ac_automata_union_matchstrs (n))
				return ACERR_ERROR;
			node_sort_edges (n);
			node_outgoing_bitmap(n);
		}

        i = path[ip].idx;

		if(!n->use || (n->one && i > 0) || !n->outgoing) {
			ip--; continue;
		}
		if(n->one && !i) {
			next = (AC_NODE_t *)n->outgoing;
		} else {
			if(i >= n->outgoing->degree) {
				ip--; continue;
			}
			next = n->outgoing->next[i];
		}

        if(!next) {
			ip--;
			continue;
        }

        path[ip].idx = i+1;
		if(ip >= AC_PATTRN_MAX_LENGTH)
			continue;
        ip++;

        path[ip].n = next;
        path[ip].idx = 0;
  }

  thiz->automata_open = 0; /* do not accept patterns any more */
  return ACERR_SUCCESS;
}

/******************************************************************************
 * FUNCTION: ac_automata_search
 * Search in the input text using the given automata. on match event it will
 * call the call-back function. and the call-back function in turn after doing
 * its job, will return an integer value to ac_automata_search(). 0 value means
 * continue search, and non-0 value means stop search and return to the caller.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * AC_TEXT_t * txt: the input text that must be searched
 * void * param: this parameter will be send to call-back function. it is
 * useful for sending parameter to call-back function from caller function.
 * RETURN VALUE:
 * -1: failed call; automata is not finalized
 *  0: success; continue searching; call-back sent me a 0 value
 *  1: success; stop searching; call-back sent me a non-0 value
 ******************************************************************************/
int ac_automata_search (AC_AUTOMATA_t * thiz, AC_MATCH_t * match,
		AC_TEXT_t * txt, MATCH_CALLBACK_f mc, acho_ret_id_t * param)
{
  unsigned long position,p_len;
  AC_NODE_t *curr;
  AC_NODE_t *next;
  unsigned char *apos;

  if(thiz->automata_open)
    /* you must call ac_automata_locate_failure() first */
    return -1;

  p_len = 0;
  position = 0;
  curr = match->start_node;
  if(!curr) curr = thiz->root;
  apos = txt->astring;
  
  /* This is the main search loop.
   * it must be keep as lightweight as possible. */
  while (position < txt->length)
    {
      if(!(next = node_findbs_next(curr, *apos++)))
		{
		  if(curr->failure_node) /* we are not in the root node */
		    curr = curr->failure_node;
		  else
		    position++;
		}
      else
		{
		  curr = next;
		  position++;
		}

      if(curr->final && next) {
	  if(mc) {
		/* We check 'next' to find out if we came here after a alphabet
		 * transition or due to a fail. in second case we should not report
		 * matching because it was reported in previous node */
		match->position = position; // + thiz->base_position;
		match->match_num = curr->matched_patterns->num;
		match->patterns = curr->matched_patterns->patterns;
		/* we found a match! do call-back */
		if (mc(match, txt, (void *)param))
		    return 1;
	  } else {
		AC_PATTERN_t * patterns=curr->matched_patterns->patterns;
		if(p_len < patterns->length) {
			param->id = patterns->rep.number;
        	param->position = position;
	       	param->name = patterns->astring;
			p_len = patterns->length;
			// return 0; // ???
		}
	  }
	}
    }
    match->start_node = curr;
  return 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_release
 * Release all allocated memories to the automata
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 ******************************************************************************/

static void _ac_automata_release (AC_AUTOMATA_t * thiz, int clean)
{
  struct ac_path *path;
  AC_NODE_t *n,*next;
  unsigned int i,ip;

  path  = thiz->ac_path;

  ip = 1;
  path[1].n = thiz->root;

  while(ip) {
	n = path[ip].n;

	if(!n->outgoing) {
		if(n != thiz->root)
				node_release(n);
		ip--; continue;
	}
	if(n->one) {
		next = (AC_NODE_t *)n->outgoing;
		n->outgoing = NULL;
	} else {
		if(n->outgoing->degree != 0) {
			i = --n->outgoing->degree;
			next = n->outgoing->next[i];
			n->outgoing->next[i] = NULL;
		} else {
			if(n != thiz->root)
					node_release(n);
			ip--; continue;
		}
	}

	if(!next) { // BUG!
		ip--; continue;
	}

	if(ip >= AC_PATTRN_MAX_LENGTH)
		continue;
	ip++;
	path[ip].n = next;
  }

  if(!clean) {
	node_release(thiz->root);
	thiz->root = NULL;
  	acho_free(thiz);
  } else {
	thiz->all_nodes_num  = 0;
	thiz->total_patterns = 0;
	thiz->max_str_len    = 0;
	thiz->automata_open  = 1;

	n = thiz->root;
	n->failure_node = NULL;
	n->id    = 0;
	n->final = 0;
	n->depth = 0;
	if(n->outgoing) acho_free(n->outgoing);
	if(n->matched_patterns) acho_free(n->matched_patterns);
	n->outgoing = NULL;
	n->matched_patterns=NULL;
	n->use = 0;
	n->one = 0;
  }
}

void ac_automata_release (AC_AUTOMATA_t * thiz) {
	_ac_automata_release(thiz,0);
}
void ac_automata_clean (AC_AUTOMATA_t * thiz) {
	_ac_automata_release(thiz,1);
}

/******************************************************************************
 * FUNCTION: ac_automata_dump
 * Prints the automata to output in human readable form. it is useful for
 * debugging purpose.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * char repcast: 'n': print AC_REP_t as number, 's': print AC_REP_t as string
 ******************************************************************************/
#ifndef __KERNEL__

static void dump_node_header(AC_NODE_t * n, size_t *mc) {
	char *c;
	int i;
	printf("%03d: failure %03d use %d",
			n->id,
			n->failure_node ? n->failure_node->id : 0,
			n->use);
	*mc += sizeof(*n);
	if(n->matched_patterns) {
		*mc += sizeof(n->matched_patterns) + n->matched_patterns->max*sizeof(n->matched_patterns->patterns);
	}
	if(!n->use) { printf("\n"); return; }
	if(n->one) {
			printf(" oc '%c' next->%d\n",n->one_alpha,
				n->outgoing ? ((AC_NODE_t *)n->outgoing)->id : -1);
			return;
	}
	if(!n->outgoing) {
			printf(" BUG! !outgoing\n");
			return;
	}
	printf("\n");
	c = edge_get_alpha(n->outgoing);
	for(i=0; i < n->outgoing->degree; i++) {
			printf("  %d: '%c' -> %d\n",i,c[i],
					n->outgoing->next[i] ? n->outgoing->next[i]->id:-1);
	}
	*mc += sizeof(n->outgoing) + edge_data_size(n->outgoing->max);

}
#endif

void ac_automata_dump(AC_AUTOMATA_t * thiz, char *rstr, size_t rstr_size, char repcast) {
#ifndef __KERNEL__
  unsigned int i, j, ip, l;
  struct ac_path *path;
  AC_NODE_t * n, *next;
  AC_PATTERN_t sid;
  AC_ALPHABET_t alpha;
  size_t memcnt = 0,memnode;

  path  = thiz->ac_path;

  printf("---DUMP- all nodes %u - max strlen %u -%s---\n",
		  (unsigned int)thiz->all_nodes_num,
		  (unsigned int)thiz->max_str_len,
		  thiz->automata_open ? "open":"ready");
  printf("root: %px\n",thiz->root);
  path[1].n = thiz->root;
  path[1].idx = 0;
  path[1].l = 0;
  ip = 1;
  *rstr = '\0';
  while(ip != 0) {

	n = path[ip].n;
	/* for debug */
	if(1 && !path[ip].idx) {
		memnode = 0;
		dump_node_header(n,&memnode);
		printf(" node size %zu\n",memnode);
		memcnt += memnode;
	}
	
	if (n->matched_patterns && n->matched_patterns->num && n->final) {
		char lbuf[300];
		int nl = 0;
		nl = snprintf(lbuf,sizeof(lbuf),"'%.100s' {",rstr);
		for (j=0; j<n->matched_patterns->num; j++)
		  {
			sid = n->matched_patterns->patterns[j];
			if(j) nl += snprintf(&lbuf[nl],sizeof(lbuf)-nl-1,", ");
			nl += snprintf(&lbuf[nl],sizeof(lbuf)-nl-1,"%d %.100s", sid.rep.number,sid.astring);
		  }
		printf("%s}\n",lbuf);
		ip--;
	 	continue;
	}
	l = path[ip].l;

	if( l >= rstr_size-1) {
		ip--; continue;
	}

	i = path[ip].idx;

	if(!n->use || (n->one && i > 0) || !n->outgoing) {
		ip--; continue;
	}
	if(n->one && !i) {
		next = (AC_NODE_t *)n->outgoing;
		alpha = n->one_alpha;
	} else {
		if(i >= n->outgoing->degree) {
			ip--; continue;
		}
		alpha = edge_get_alpha(n->outgoing)[i];
		next = n->outgoing->next[i];
	}

	path[ip].idx = i+1;

	if(ip >= AC_PATTRN_MAX_LENGTH)
		continue;
	ip++;

	rstr[l] = alpha;
	rstr[l+1] = '\0';

	path[ip].n = next;
	path[ip].idx = 0;
	path[ip].l = l+1;
  }
  printf("---\n mem size %zu avg node size %d\n---DUMP-END-\n",
			  memcnt,(int)memcnt/(thiz->all_nodes_num+1));

#endif
}

/******************************************************************************
 * FUNCTION: ac_automata_union_matchstrs
 * Collect accepted patterns of the node. the accepted patterns consist of the
 * node's own accepted pattern plus accepted patterns of its failure node.
 ******************************************************************************/
static int ac_automata_union_matchstrs (AC_NODE_t * node)
{
  unsigned int i;
  AC_NODE_t * m;

  for (m = node; m; m = m->failure_node) {
	  if(!m->matched_patterns) continue;

      for (i=0; i < m->matched_patterns->num; i++)
		if(node_register_matchstr(node, &(m->matched_patterns->patterns[i])))
		return 1;

      if (m->final)
		node->final = 1;
    }
  return 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_set_failure
 * find failure node for the given node.
 ******************************************************************************/
static void ac_automata_set_failure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, struct ac_path * path)
{
  unsigned int i, j;
  AC_NODE_t * m;

  for (i=1; i < node->depth; i++) {
		m = thiz->root;
		for (j=i; j < node->depth && m; j++) {
			m = node_find_next (m, path[j].l);
		}
		if (m) {
		  node->failure_node = m;
		  break;
		}
  }
  if (!node->failure_node)
	node->failure_node = thiz->root;
}

/******************************************************************************
 * FUNCTION: ac_automata_traverse_setfailure
 * Traverse all automata nodes using DFS (Depth First Search), meanwhile it set
 * the failure node for every node it passes through. this function must be
 * called after adding last pattern to automata. i.e. after calling this you
 * can not add further pattern to automata.
 ******************************************************************************/
static void ac_automata_traverse_setfailure
(AC_AUTOMATA_t * thiz)
{
  unsigned int i,ip;
  AC_NODE_t *next, *node;
  struct ac_path * path = thiz->ac_path;

  ip = 1;
  path[1].n = thiz->root;
  path[1].idx = 0;

  while(ip) {
	node = path[ip].n;
	i = path[ip].idx;

	if(!node->use || (node->one && i > 0) || !node->outgoing) {
		ip--; continue;
	}
	if(node->one && !i) {
		next = (AC_NODE_t *)node->outgoing;
	} else {
		if(i >= node->outgoing->degree) {
			ip--; continue;
		}
		next = node->outgoing->next[i];
	}

	if(node->depth < AC_PATTRN_MAX_LENGTH) {
			path[node->depth].l = node->one ? node->one_alpha:
									edge_get_alpha(node->outgoing)[i];
			/* At every node look for its failure node */
			ac_automata_set_failure (thiz, next, path);
	}

	path[ip].idx = i+1;
   	if(ip >= AC_PATTRN_MAX_LENGTH)
		continue;
	ip++;

	path[ip].n = next;
	path[ip].idx = 0;
  }
}


/******************************************************************************
 * FUNCTION: node_create
 * Create the node
 ******************************************************************************/
static AC_NODE_t * node_create(void)
{
  return  (AC_NODE_t *) acho_calloc (1,sizeof(AC_NODE_t));
}

/******************************************************************************
 * FUNCTION: node_release
 * Release node
 ******************************************************************************/
static void node_release(AC_NODE_t * thiz)
{
  if(thiz->matched_patterns) {
	acho_free(thiz->matched_patterns);
	thiz->matched_patterns = NULL;
  }
  if(!thiz->one && thiz->outgoing) {
	acho_free(thiz->outgoing);
  }
  thiz->outgoing = NULL;
  acho_free(thiz);
}

/******************************************************************************
 * FUNCTION: node_find_next
 * Find out the next node for a given Alpha to move. this function is used in
 * the pre-processing stage in which edge array is not sorted. so it uses
 * linear search.
 ******************************************************************************/
static AC_NODE_t * node_find_next(AC_NODE_t * thiz, AC_ALPHABET_t alpha)
{
  int i;
  AC_ALPHABET_t  *alphas;

  if(thiz->one) return alpha == thiz->one_alpha ? (AC_NODE_t *)thiz->outgoing:NULL;
  if(!thiz->outgoing) return NULL;

  alphas = edge_get_alpha(thiz->outgoing);
  for (i=0; i < thiz->outgoing->degree; i++)
    {
      if(alphas[i] == alpha) {
		return thiz->outgoing->next[i];
      }
    }
  return NULL;
}

/******************************************************************************
 * FUNCTION: node_findbs_next
 * Find out the next node for a given Alpha. this function is used after the
 * pre-processing stage in which we sort edges. so it uses Binary Search.
 ******************************************************************************/
static AC_NODE_t * node_findbs_next (AC_NODE_t * thiz, AC_ALPHABET_t alpha)
{
  int min, max, mid;
  AC_ALPHABET_t amid;
  AC_ALPHABET_t  *alphas;
 
  if(!thiz->outgoing) return NULL;

  if(thiz->one) return alpha == thiz->one_alpha ? (AC_NODE_t *)thiz->outgoing:NULL;

  alphas = edge_get_alpha(thiz->outgoing);

  if(!(thiz->outgoing->cmap[alpha >> 5] & (1 << (alpha & 0x1f)))) {
		  return NULL;
  }

  min = 0;
  max = thiz->outgoing->degree - 1;

  while (min <= max)
    {
      mid = (min+max) >> 1;
      amid = alphas[mid];
      if (alpha > amid)
		min = mid + 1;
      else if (alpha < amid)
			max = mid - 1;
	      else
			return (thiz->outgoing->next[mid]);
    }
  return NULL;
}

/******************************************************************************
 * FUNCTION: node_has_matchstr
 * Determine if a final node contains a pattern in its accepted pattern list
 * or not. return values: 1 = it has, 0 = it hasn't
 ******************************************************************************/
static int node_has_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * newstr)
{
  int i;
  AC_PATTERN_t * str;
  if(!thiz->matched_patterns) return 0;
  str = thiz->matched_patterns->patterns;

  for (i=0; i < thiz->matched_patterns->num; str++,i++)
    {
      if (str->length != newstr->length)
		continue;

	  if(!memcmp(str->astring,newstr->astring,str->length))
		return 1;

    }
  return 0;
}

/******************************************************************************
 * FUNCTION: node_create_next
 * Create the next node for the given alpha.
 ******************************************************************************/
static AC_NODE_t * node_create_next (AC_NODE_t * thiz, AC_ALPHABET_t alpha)
{
  AC_NODE_t * next;
  next = node_find_next (thiz, alpha);
  if (next)
    /* The edge already exists */
    return NULL;
  /* Otherwise register new edge */
  next = node_create ();
  if(next) {
	if(node_register_outgoing(thiz, next, alpha)) {
		node_release(next);
		return NULL;
	}
	next->depth = thiz->depth+1;
  }

  return next;
}

static inline int mp_data_size(int n) {
	return sizeof(AC_PATTERNS_t) + n*sizeof(AC_PATTERN_t);
}

static AC_PATTERNS_t * node_resize_mp(AC_PATTERNS_t *m) {
AC_PATTERNS_t *new_m;

	if(!m) {
		m = acho_calloc(1,mp_data_size(REALLOC_CHUNK_MATCHSTR));
		if(!m) return m;
		m->max = REALLOC_CHUNK_MATCHSTR;
		return m;
	}
	new_m = acho_malloc(mp_data_size(m->max+REALLOC_CHUNK_MATCHSTR));
	if(!new_m) return new_m;
	memcpy((char *)new_m,(char *)m,mp_data_size(m->max));
	new_m->max += REALLOC_CHUNK_MATCHSTR;
	acho_free(m);
	return new_m;
}

/******************************************************************************
 * FUNCTION: node_register_matchstr
 * Adds the pattern to the list of accepted pattern.
 ******************************************************************************/
static int node_register_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * str)
{
  AC_PATTERN_t *l;
  /* Check if the new pattern already exists in the node list */
  if (thiz->matched_patterns && node_has_matchstr(thiz, str))
    return 0;

  if(!thiz->matched_patterns)
	thiz->matched_patterns = node_resize_mp(thiz->matched_patterns);

  /* Manage memory */
  if (thiz->matched_patterns->num >= thiz->matched_patterns->max) {
      AC_PATTERNS_t *new_mp = node_resize_mp(thiz->matched_patterns);
      if(!new_mp) return 1;
      thiz->matched_patterns = new_mp; 
    }
  l = &thiz->matched_patterns->patterns[thiz->matched_patterns->num];
  l->astring = str->astring;
  l->length  = str->length;
  l->rep = str->rep;
  thiz->matched_patterns->num++;
  return 0;
}

static struct edge *node_resize_outgoing(struct edge * e) {
struct edge *new_e;
int ds;

	if(!e) {
		e = acho_calloc(1,sizeof(struct edge) + edge_data_size(REALLOC_CHUNK_OUTGOING));
		if(!e) return e;
		e->max = REALLOC_CHUNK_OUTGOING;
		return e;
	}
	ds = edge_data_size(e->max + REALLOC_CHUNK_OUTGOING);
	new_e = acho_calloc(1,sizeof(struct edge) + ds);
	if(!new_e) return new_e;
	memcpy(new_e,e,sizeof(struct edge) + sizeof(AC_NODE_t *)*e->max);
	new_e->max += REALLOC_CHUNK_OUTGOING;

	if(e->degree)
		memcpy(edge_get_alpha(new_e),edge_get_alpha(e),e->degree);

	acho_free(e);
	return new_e;
}

/******************************************************************************
 * FUNCTION: node_register_outgoing
 * Establish an edge between two nodes
 ******************************************************************************/
static int node_register_outgoing
(AC_NODE_t * thiz, AC_NODE_t * next, AC_ALPHABET_t alpha)
{
  struct edge *o;
  if(!thiz->use) {
		thiz->use = 1;
		thiz->one = 1;
		thiz->one_alpha = alpha;
		thiz->outgoing = (struct edge *)next;
		return 0;
  }
  if(thiz->one) {
		o = node_resize_outgoing(NULL);
		if(!o) return 1;
		o->next[0] = (AC_NODE_t *)thiz->outgoing;
		*edge_get_alpha(o) = thiz->one_alpha;
		o->degree = 1;
		thiz->one = 0;
		thiz->outgoing = o;
  } else
		o = thiz->outgoing;
  if(!o) return 1;
 
  if(o->degree >= o->max)
    {
    	struct edge *new_o = node_resize_outgoing(thiz->outgoing);
		if(!new_o) return 1;

		thiz->outgoing = new_o;
		o = new_o;
    }
  edge_get_alpha(o)[o->degree] = alpha;
  o->next[o->degree] = next;
  o->degree++;
  return 0;
}

/******************************************************************************
 * FUNCTION: node_edge_compare
 * Comparison function for qsort. see man qsort.
 ******************************************************************************/
static int node_edge_compare (struct edge * e, int a, int b) {
	AC_ALPHABET_t *c = edge_get_alpha(e);
	return c[a] >= c[b] ? 1:-1;
}

static void node_edge_swap (struct edge * e, int a, int b)
{
AC_ALPHABET_t *c,tc;
AC_NODE_t *tn;
	c = edge_get_alpha(e);
	tc = c[a]; c[a] = c[b]; c[b] = tc;
	tn = e->next[a]; e->next[a] = e->next[b]; e->next[b] = tn;
}

/******************************************************************************
 * FUNCTION: node_sort_edges
 * sorts edges alphabets.
 ******************************************************************************/
static void node_sort_edges (AC_NODE_t * thiz)
{
  if(!thiz->use || thiz->one || !thiz->outgoing) return;

  acho_sort (thiz->outgoing, thiz->outgoing->degree, 
		node_edge_compare, node_edge_swap);
}

/**
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap_func function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */

 void acho_sort(struct edge *e, size_t num,
	  int (*cmp_func)(struct edge *e, int a, int b),
	  void (*swap_func)(struct edge *e, int a, int b))
{
  /* pre-scale counters for performance */
  int i = (num/2 - 1) , n = num, c, r;

  if (!swap_func) return;
  if (!cmp_func) return;

  /* heapify */
  for ( ; i >= 0; i -= 1) {
    for (r = i; r * 2 + 1 < n; r = c) {
      c = r * 2 + 1;
      if (c < n - 1 && cmp_func(e, c, c + 1) < 0)
			c += 1;
      if (cmp_func(e, r, c) >= 0)
			break;
      swap_func(e, r, c);
    }
  }

  /* sort */
  for (i = n - 1; i > 0; i -= 1) {
    swap_func(e,0,i);
    for (r = 0; r * 2 + 1 < i; r = c) {
      c = r * 2 + 1;
      if (c < i - 1 && cmp_func(e, c, c + 1) < 0)
		c += 1;
      if (cmp_func(e, r, c) >= 0)
		break;
      swap_func(e, r, c);
    }
  }
}

/* vim: set ts=4:  */

