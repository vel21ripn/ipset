/* Copyright (C) 2005 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

/* Kernel module implementing an IP set type: the ipcidr type */

#undef IP_SET_DEBUG
//#define IP_SET_DEBUG 1

#include <linux/version.h>

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_ipcidr.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
MODULE_IMPORT_NS(NET_IPSET);
#endif

//#define IP_SET_DEBUG
#ifdef IP_SET_DEBUG
//#define DP(fmt, args...)
#undef DP
#define DP(fmt, args...) printk(fmt, ## args)
#define DBGDATA(a...) a;
#warning  "DEBUG code"
#else
#define DP(fmt, args...)
#define DBGDATA(a...)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
#error "Only for > 2.6.39"
#endif

static uint32_t l2m[64]={ 
    0x0,0x80000000,0xc0000000,0xe0000000,0xf0000000,
	0xf8000000,0xfc000000,0xfe000000,0xff000000,
	0xff800000,0xffc00000,0xffe00000,0xfff00000,
	0xfff80000,0xfffc0000,0xfffe0000,0xffff0000,
	0xffff8000,0xffffc000,0xffffe000,0xfffff000,
	0xfffff800,0xfffffc00,0xfffffe00,0xffffff00,
	0xffffff80,0xffffffc0,0xffffffe0,0xfffffff0,
	0xfffffff8,0xfffffffc,0xfffffffe,0xffffffff};
static uint32_t nbm[34]={
	0x80000000,0x40000000,0x20000000,0x10000000,
	0x08000000,0x04000000,0x02000000,0x01000000,
	0x00800000,0x00400000,0x00200000,0x00100000,
	0x00080000,0x00040000,0x00020000,0x00010000,
	0x00008000,0x00004000,0x00002000,0x00001000,
	0x00000800,0x00000400,0x00000200,0x00000100,
	0x00000080,0x00000040,0x00000020,0x00000010,
	0x00000008,0x00000004,0x00000002,0x00000001,
	0};

struct _netlist {
	u32	ip;
	int		masklen;
	};

struct one_string {
	struct list_head list;
	atomic_t	ref;
	uint8_t		str_len;
	char		str[1];
};

static int _compress(tree_node_t *n,int force, struct ip_set_ipcidr *map);

#ifdef IP_SET_DEBUG

#define HIPQUAD(i) (i) >> 24 & 0xff,(i) >> 16 & 0xff,(i) >> 8 & 0xff,(i) & 0xff

static char *__str_ip(u32 ip,char *buf)
{
unsigned char *p = (unsigned char *)&ip;
sprintf(buf,"%u.%u.%u.%u",(u32)p[3],(u32)p[2],(u32)p[1],(u32)p[0]);
return buf;
}
static char * __print_node(tree_node_t *n,char *buf,int size)
{
int l;
char b[256];
	__str_ip(n->ip,b);
	l = strlen(b);
	l += snprintf(&b[l],sizeof(b)-l,"/%d a:%d",n->mlen, n->f_act);
	if(n->f_tmo)
		l += snprintf(&b[l],sizeof(b)-l," tm:%lu", n->expired);
	if(n->f_mark)
		l += snprintf(&b[l],sizeof(b)-l," m:%x/%x", n->mark, n->mask);
	if(n->f_prio)
		l += snprintf(&b[l],sizeof(b)-l," p:%x",n->prio);
	if(n->f_cnt) {
		struct ip_set_counter *cnt = (struct ip_set_counter *)
			((char *)n + sizeof(*n));
		l += snprintf(&b[l],sizeof(b)-l," cnt %d %d",
			(int)atomic64_read(&cnt->packets),
			(int)atomic64_read(&cnt->bytes));
	}
	if(n->f_strlen) {
		struct one_string **cnt = (struct one_string **)
			((char *)n + sizeof(*n) + 
			   (n->f_cnt ? sizeof(struct ip_set_counter): 0));
		if(*cnt)
		 l += snprintf(&b[l],sizeof(b)-l," com ref %d %d:%s",
			atomic_read(&(*cnt)->ref),(*cnt)->str_len,(*cnt)->str);
	}
	strncpy(buf,b,size-1);
	return buf;
}
#endif

static inline int net_in_net(tree_node_t *n,tree_node_t *s)
{
if(!n || !s) return 0;
return (s->ip & l2m[n->mlen]) == n->ip && s->mlen >= n->mlen;
}

static struct one_string *alloc_one_string(struct ip_set_ipcidr *map, char *str) {
	size_t str_len;
	struct one_string *s;

	if(!str) return NULL;
	str_len = strlen(str);
	if(str_len > 254) str_len = 254;
	s = (struct one_string *)kmalloc(sizeof(struct one_string) + str_len, GFP_ATOMIC);
	if(!s) return s;

	INIT_LIST_HEAD(&s->list);
	s->str_len = str_len;
	atomic_set(&s->ref,1);
	memcpy(&s->str,str,str_len+1);
	spin_lock(&map->str_lock);
	list_add_tail(&s->list,&map->str);
	spin_unlock(&map->str_lock);
	DP("%s (%s, %s) alloc\n",__func__,map->set->name,str);
	return s;
}

static struct one_string *find_one_string(struct ip_set_ipcidr *map, char *str) {
	struct list_head *listptr;
	struct one_string *s;
	size_t str_len;

	if(!str) return NULL;
	str_len = strlen(str);
	if(str_len > 254) str_len = 254;

	spin_lock(&map->str_lock);
	list_for_each(listptr, &map->str) {
		s = list_entry(listptr, struct one_string, list);
		if( s->str_len == str_len &&
		    !memcmp(str,&s->str,str_len)) {
			spin_unlock(&map->str_lock);
			DP("%s (%s, %s) OK\n",__func__,map->set->name,str);
			return s;
		}
	}
	spin_unlock(&map->str_lock);
	DP("%s (%s, %s) NO\n",__func__,map->set->name,str);
	return NULL;
}

static int free_one_string(struct one_string *s) {
	if(atomic_dec_return(&s->ref) > 0) {
		DP("%s %s in use\n",__func__,s->str);
		return 1;
	}
	list_del(&s->list);
	DP("%s %s free\n",__func__,s->str);
	kfree(s);
	return 0;
}

static void free_one_str(struct ip_set_ipcidr *map) {
	struct list_head *listptr,*q;
	struct one_string *s;

	spin_lock(&map->str_lock);
	list_for_each_safe(listptr,q, &map->str) {
		s = list_entry(listptr, struct one_string, list);
		if(free_one_string(s))
			DP("%s BUG! %s : %s busy\n",__func__,map->set->name,s->str);
	}
	spin_unlock(&map->str_lock);
}

static inline void print_one_str(struct ip_set_ipcidr *map) {
#ifdef IP_SET_DEBUG
	struct list_head *listptr;
	struct one_string *s;

	spin_lock(&map->str_lock);
	list_for_each(listptr, &map->str) {
		s = list_entry(listptr, struct one_string, list);
		DP("%s %s ref %d : %s \n",__func__,map->set->name,
				atomic_read(&s->ref),s->str);
	}
	spin_unlock(&map->str_lock);
#endif
}

static size_t total_one_str(struct ip_set_ipcidr *map) {
	struct list_head *listptr;
	struct one_string *s;
	size_t size = 0;

	spin_lock(&map->str_lock);
	list_for_each(listptr, &map->str) {
		s = list_entry(listptr, struct one_string, list);
		size += s->str_len;
	}
	spin_unlock(&map->str_lock);
	return size;
}

static struct ip_set_counter *get_counters(const struct ip_set *set,tree_node_t *n) {
	if(!SET_WITH_COUNTER(set) || !n->f_cnt) return NULL;
	return (void *)(char *)n + sizeof(*n);
}

static struct one_string **get_comment(const struct ip_set *set,tree_node_t *n) {
char *p;
	if(!SET_WITH_COMMENT(set)) return NULL;
	p = (char *)n + sizeof(*n);
	if(SET_WITH_COUNTER(set))
		p += sizeof(struct ip_set_counter);
	return (struct one_string **)p;
}

static tree_node_t *alloc_node(u32 ip,u32 mlen,struct ip_set_ipcidr *map,struct one_string *str)
{
tree_node_t *t;
const struct ip_set *set = map->set;
char *p;

	t = (tree_node_t *)kmalloc(set->dsize, GFP_ATOMIC);
	if(!t) return NULL;
	map->node_count++;
	memset((char *)t,0,set->dsize);
	t->ip = ip;
	t->mlen = mlen;
	t->expired = 0;
	t->mark = 0;
	t->mask = ~0;
	t->l0 = NULL;
	t->l1 = NULL;
	t->f_act = 0;
	t->f_tmo = 0;
	t->f_mark = 0;
	p = (char *)t + sizeof(*t);
	t->f_cnt = SET_WITH_COUNTER(set) ? 1:0;
	if(t->f_cnt)
		p += sizeof(struct ip_set_counter);

	if(SET_WITH_COMMENT(set) && str) {
		t->f_strlen = str->str_len;
		if(t->f_strlen != 0) {
		    atomic_inc(&str->ref);
		    WRITE_ONCE(*(struct one_string **)p,str);
		}
	}

	DP("\nAlloc nodes ++%d\n",map->node_count);
	return t;
}

static tree_node_t *clone_node(tree_node_t *src,struct ip_set_ipcidr *map)
{
tree_node_t *t;
const struct ip_set *set = map->set;

	t = (tree_node_t *) kmalloc(set->dsize,  GFP_ATOMIC);
	if(!t) return NULL;
	map->node_count++;
	memcpy((char *)t,(char *)src,set->dsize);
	if(SET_WITH_COMMENT(set)) {
		struct one_string **str = get_comment(set,src);
		if(str && *str) atomic_add(1,&(*str)->ref);
	}
	DP("\nclone nodes ++%d\n",map->node_count);
	return t;
}

static inline void free_node_comment(tree_node_t *n,struct ip_set_ipcidr *map)
{
const struct ip_set *set = map->set;
struct one_string **str;

	if(!(n && SET_WITH_COMMENT(set))) return;
	spin_lock(&map->str_lock);
	str = get_comment(set,n);
	if(str && *str) {
		free_one_string(*str);
		WRITE_ONCE(*str,NULL);
	}
	spin_unlock(&map->str_lock);
}

static void free_node(tree_node_t *n,struct ip_set_ipcidr *map)
{
	if(!n) return;
	free_node_comment(n,map);
	kfree(n);
	map->node_count--;
	DP("\nfree nodes --%d\n",map->node_count);
}

static inline void deactivate(tree_node_t *a, struct ip_set_ipcidr *map)
{
	free_node_comment(a,map);
	a->f_act = 0;
	a->f_tmo = 0;
	a->f_mark = 0; 
	a->expired = 0;
	a->mark = 0;
	a->f_cnt = 0;
	a->f_strlen = 0;
}

static inline void check_expires(tree_node_t *n,unsigned long t_exp,
		struct ip_set_ipcidr *map)
{
if(!n) return;
if(!n->f_act) return;
if(n->f_tmo && n->expired && !time_after(n->expired,t_exp))
	deactivate(n,map);
}



static int eq_node(tree_node_t *t,tree_node_t *rq,struct ip_set *set) {
if(!t->f_act) return 0;
if(t->f_mark != rq->f_mark) return 0;
if(t->f_mark && (t->mark != rq->mark || t->mark != rq->mark)) return 0;
if(t->f_prio != rq->f_prio) return 0;
if(t->f_prio && (t->prio != rq->prio)) return 0;
if(t->f_tmo != rq->f_tmo) return 0;
if(t->f_cnt != rq->f_cnt) return 0;
{
  struct one_string **t_str,**rq_str;
  t_str = get_comment(set,t);
  rq_str = get_comment(set,rq);
  if((t_str != NULL) != (rq_str != NULL)) return 0;
  if(t_str && rq_str && *t_str != *rq_str) return 0;
}
if(!t->f_tmo) return 1;
return (( t->expired > rq->expired ? 
	 t->expired - rq->expired : rq->expired - t->expired)/HZ) == 0;
}

static int split2node(tree_node_t *t,struct ip_set_ipcidr *map)
{
DBGDATA(char _ip1[64])

	tree_node_t *t0,*t1;
	uint32_t m;

	DP("\nsplit\n\ttree:%s ,\n",
		__print_node(t,_ip1,sizeof(_ip1)));
	t0 = clone_node(t,map);
	if(!t0) return 1;
	t0->mlen++;
	t0->l0 = NULL; t0->l1 = NULL;

	t1 = clone_node(t0,map);
	if(!t1) { free_node(t0,map); return 1; }
	t1->ip += 1 << (32 - t1->mlen);

	m = l2m[t0->mlen];
	if(t->l0) {
		if(t->l0->ip & m) t0->l1 = t->l0;  else t0->l0 = t->l0;
	}
	t->l0 = t0;
	if(t->l1) {
		if(t->l1->ip & m) t1->l1 = t->l1;  else t1->l0 = t->l1;
	}
	t->l1 = t1;
	deactivate(t,map);
	return 0;
}

static int r2l(uint32_t ip1,uint32_t ip2,struct _netlist *l,int ll)
{
uint32_t m,m1;
int n,rl;
if(ip1 > ip2) { uint32_t t = ip1; ip1 = ip2; ip2 = t; }

rl = 0;
do {
   for(n=0,m=0xfffffffful; m; n++,m <<=1) {
	m1 = ~(m << 1);
	if(ip1 & m1) break;
	if(ip1 + m1 > ip2) break;
   }
   m1 = ~m + 1;
   if(rl < ll) {
	DP("r2l %u.%u.%u.%u %u\n", HIPQUAD(ip1), 32-n);
	l->ip = ip1;
	l->masklen = 32-n;
	l++;
	rl++;
   } else break;
   if(ip1 == ~0ul) break;
   ip1 += m1;
} while(ip1 <= ip2);
return rl;
}

static int ip_may_merge(const tree_node_t *p,const tree_node_t *n) {
  return p->mlen == n->mlen && p->ip + (1 << ( 32 - p->mlen )) == n->ip &&
	 p->mlen > 1 && (p->ip & (0xfffffffful << (33 - p->mlen))) == p->ip;
}

static int _compress(tree_node_t *n,int force,struct ip_set_ipcidr *map)
{
DBGDATA(char _ip1[64])
if(!n) return 1;
DP("%s %s jiffies %ld\n",force ? "remove":"check",__print_node(n,_ip1,sizeof(_ip1)),jiffies);

if(n->l0 && _compress(n->l0,force,map)) 
	n->l0 = NULL;

if(n->l1 && _compress(n->l1,force,map))
	n->l1 = NULL;

if(force) {
	free_node(n,map);
	return 1;
}

if( ((!!n->l0) ^ (!!n->l1)) && !n->f_act ) {
	tree_node_t *t = n->l0 ? n->l0 : n->l1;
	DP("   %s ",__print_node(n,_ip1,sizeof(_ip1)));
	DP(" squeezed %s\n",__print_node(t,_ip1,sizeof(_ip1)));
	*n = *t; free_node(t,map);
}
check_expires(n, jiffies, map);

if(n->l0 && n->l1 && n->l0->f_act && n->l1->f_act) {
   if(n->f_act) {
	DP("BUG f_act %s\n",__print_node(n,_ip1,sizeof(_ip1)));
   } else {
	if(eq_node(n->l0, n->l1, map->set) && ip_may_merge(n->l0,n->l1)) {
		DP(" merged1 %s\n",__print_node(n->l0,_ip1,sizeof(_ip1)));
		DP(" merged2 %s\n",__print_node(n->l1,_ip1,sizeof(_ip1)));
		n->ip = n->l0->ip;
		n->mlen = n->l0->mlen-1;
		n->f_act = 1;
		n->expired = n->l0->expired;
		n->mark = n->l0->mark;
		n->mask = n->l0->mask;
		n->prio = n->l0->prio;
		n->f_tmo = n->l0->f_tmo;
		n->f_mark = n->l0->f_mark;
		n->f_prio = n->l0->f_prio;
		_compress(n->l0,1,map);
		_compress(n->l1,1,map);
		n->l0 = NULL;
		n->l1 = NULL;
		DP(" result %s\n",__print_node(n,_ip1,sizeof(_ip1)));
	}
   }
}
if(n->l0 || n->l1 || n->f_act) return 0;
if(!n->ip && !n->mlen) return 0;
DP("   %s deleted\n",__print_node(n,_ip1,sizeof(_ip1))); 
free_node(n,map);

return 1;
}

static void u_compress(struct ip_set *set)
{
	struct ip_set_ipcidr * map = set->data;
	if(map->tree) {
		if(map->tree->l0 &&  _compress(map->tree->l0,0,map)) map->tree->l0=NULL;
		if(map->tree->l1 &&  _compress(map->tree->l1,0,map)) map->tree->l1=NULL;
	}
}

/*********************************************************************************/

static int
__testip(struct ip_set *set, u32 ip, tree_node_t **rt)
{
struct ip_set_ipcidr *map;
DBGDATA(char _ip1[20],_ip2[20])
tree_node_t *t,*lt;
u32 m;
int c;

	if(!set) return 0;
	map = (struct ip_set_ipcidr *)set->data;

	if(!(t = map->tree)) return 0;
	DP("  test ip %s set %s;",__str_ip(ip,_ip1),set->name);
	c = 0;
	lt = NULL;
	do {
		auto uint32_t tmask = l2m[t->mlen];
		DP("   %s == %s ?",__str_ip(ip & tmask,_ip1),
				__str_ip(t->ip,_ip2));

		if((ip & tmask) != t->ip) break;
		if(t->f_act) {
		    if(t->f_tmo) {
			if(t->expired) {
			   if(time_after(t->expired, jiffies)) {
			   	lt = t; break;
			   } else
			   	deactivate(t, map);
			}
			DP("    expired %ld",
				t->f_act && t->expired ? jiffies - t->expired : 0);
		    } else {
			lt = t; break;
		    }
		}
		m=nbm[t->mlen];
		t = ip & m ? t->l1:t->l0;
		if(t) DP("   next node %s/%d",__str_ip(t->ip,_ip1),t->mlen);
	} while (t && ++c < 32);

	if(lt && lt->f_act) {
		if(!lt->f_tmo || lt->expired) {
			if(rt) *rt = lt;
			DP("    return 1\n");
			return 1;
		}
	}
	DP("    return 0\n");
	if(c >= 32) DP("BUG!\n");
	return 0;
}

static int
__addip(struct ip_set *set, tree_node_t *rq, int op, 
		struct one_string *o_str,
		struct ip_set_counter *o_cnt)
{
struct ip_set_ipcidr *map = (struct ip_set_ipcidr *)set->data;

DBGDATA(char _ip1[64],_ip2[20])
u32 ip;
tree_node_t *t,*n,*p,*pa;
u32 mask,m;
int c=0;
uint32_t tmask;

	DP("%s %s '%s' %d:%s %d:%s\n",op ? "ADD":"DEL",
		__print_node(rq,_ip1,sizeof(_ip1)),set->name,
		rq->f_strlen, o_str ? "COM":"",
		rq->f_cnt, o_cnt ? "CNT":"");
	ip = rq->ip;
	if(rq->mlen > 32) return -EINVAL;
	mask = l2m[rq->mlen];
	if((ip & mask) != ip) return -EINVAL;

	if(!(t = map->tree)) {
		t = map->tree = alloc_node(0,0,map,NULL);
		if(!map->tree) return -ENOMEM;
	}
	p = t;
	pa = NULL;
	do {
	    tmask = l2m[t->mlen];
	    DP("   %s / %d == %s / %d = %d ",
			    __str_ip(ip,_ip1),rq->mlen,
			    __str_ip(t->ip,_ip2),t->mlen,
			    (ip & tmask) == t->ip);

	    if((ip & tmask) == t->ip) { // request in this network

		if( rq->mlen <= t->mlen ) { // overlay exist network
		    DP("    found.\n");
		    _compress(t->l0,1,map); t->l0 = NULL;
		    _compress(t->l1,1,map); t->l1 = NULL;
		    if(op) { // ADD
			t->f_act  = 1;
			t->mlen   = rq->mlen;
			t->f_mark = rq->f_mark;
			t->mark   = rq->f_mark ? rq->mark : 0;
			t->mask   = rq->f_mark ? rq->mask : ~0ul;
			t->f_prio = rq->f_prio;
			t->prio   = rq->f_prio ? rq->prio : 0;
			t->f_tmo  = rq->f_tmo;
			t->expired = rq->f_tmo ? (
				!t->expired || time_after(rq->expired,t->expired) ? 
							rq->expired : t->expired ) : 0;
			t->f_cnt = rq->f_cnt;
			if(t->f_cnt && o_cnt) {
			    struct ip_set_counter *t_cnt = get_counters(set,t);
			    if(t_cnt) *t_cnt = *o_cnt;
			}
			spin_lock(&map->str_lock);
			{
			    struct one_string **t_str = get_comment(set,t);
			    if(t_str) {
				if(*t_str) free_one_string(*t_str);
				if(o_str) atomic_inc(&o_str->ref);
				*t_str = o_str;
			    }
			}
			t->f_strlen = o_str ? o_str->str_len:0;
			spin_unlock(&map->str_lock);

			DP("new value %s\n",__print_node(t,_ip1,sizeof(_ip1)));
		    } else { // DEL
			DP("remove %s\n",__print_node(t,_ip1,sizeof(_ip1)));
			if(t == map->tree) {
				deactivate(t, map);
			} else {
			    	if(p->l0 == t) p->l0 = NULL;
			    	if(p->l1 == t) p->l1 = NULL;
				free_node(t,map);
			}
		    }
		    return 0;
		}
		// t->mlen < rq->mlen -> continue search
		// 10.0.0.0/24 exist, request 10.0.0.0/28
		p = t;

		DP("   mask not match");

		if(op && net_in_net(t,rq) && eq_node(t,rq,set)) {
			// adding subnetwork with same options
			DP("   eq_node\n");
			return 0;
		}

		m = nbm[t->mlen];
		n = ip & m ? t->l1:t->l0;
		if(n) {
			t = n;
			DP("   next node L%d %s\n", !!(ip & m),
				__print_node(t,_ip1,sizeof(_ip1)));
			continue;
		} else {
			if(!op) {
				if(!t->f_act) {
					DP("  nothing delete\n");
					return 0;
				}
				if(split2node(t,map)) return -ENOMEM;
			} else {
			    if(t->f_act) {
				if(split2node(t,map)) return -ENOMEM;
				DP("   split node %s/%d : L%d\n",
					__str_ip(t->ip,_ip1),t->mlen,!!(ip & m));

				m = nbm[t->mlen];
				n = ip & m ? t->l1:t->l0;
				if(!n) {
					DP("BUG!\n");
					return -ENOMEM;
				}
			    } else {

				n = alloc_node(ip,rq->mlen,map,NULL);
				if(!n) return -ENOMEM;

				if(ip & m) t->l1 = n; else t->l0 = n;
			    }
			    t = n;
			}
			continue;
		}

	    } else { // ip & mask != t->ip
		DP("   ip not match\n");
		if(!op) {
			if(net_in_net(rq,t)) {
				tree_node_t **pt;
				pt = p->l0 == t ? &p->l0:&p->l1;
				DP(" delete it %s\n",__print_node(*pt,_ip1,sizeof(_ip1)));
				_compress(*pt,1,map);
				*pt = NULL;
			}
			return 0;
		}
		t = p;
		DP("   parent node %s ", __print_node(t,_ip1,sizeof(_ip1)));

		m = nbm[t->mlen];
		n = ip & m ? t->l1:t->l0;
		if(n) {
			int f=0;
			tree_node_t *t1;
			int nml = n->mlen;

			while(nml > t->mlen) {
				m = l2m[nml];
				if((ip & m) != (n->ip & m)) nml--;
				  else { f=1; break; }
			}
			m = l2m[nml];
			if(!f) {
				DP("BUG n %s\n",__print_node(n,_ip1,sizeof(_ip1)));
				DP("BUG insert 1 nml %d t->mlen %d\n",nml,t->mlen);
				return -EINVAL; 
			}
			t1 = clone_node(n, map);
	    		if(!t1) return -ENOMEM;
			deactivate(n, map);
			n->mlen = nml;
			n->ip &= l2m[n->mlen];
			m = nbm[n->mlen];
			if(t1->ip & m) {
				n->l1 = t1; n->l0 = NULL;
			} else {
				n->l0 = t1; n->l1 = NULL;
			}
			DP("insert to %s\n",__print_node(n,_ip1,sizeof(_ip1)));
			t = n;
			continue;
		}
		n = alloc_node(ip,rq->mlen,map,NULL);
		if(!n) return -ENOMEM;

		if(ip & m) t->l1 = n; else t->l0 = n;
		t = n;
	    }

	} while (++c <= 64);
	if(c > 64) DP("BUG!\n");
	return -EINVAL;
}

/**************************************************************************/

static int
ipcidr_kadt(struct ip_set *set, const struct sk_buff *skb,
		const struct xt_action_param *par,
		enum ipset_adt adt,
		struct ip_set_adt_opt *opt)
{
	struct ip_set_ipcidr *map;
	u32 ip;
	int res;


	if(!set) return -IPSET_ERR_PROTOCOL;
	map = READ_ONCE(set->data);
	if(!map) 
		return -EINVAL;
	
	ip = htonl(ip4addr(skb, opt->flags & IPSET_DIM_ONE_SRC));
	switch(adt) {
	  case IPSET_TEST:
		  	{
			tree_node_t *fq = NULL;
			spin_lock_bh(&set->lock);
			res =  __testip(set,ip, &fq);
			spin_unlock_bh(&set->lock);
			if(res >= 0) {
				if(fq) {
				    struct ip_set_counter *o_cnt = get_counters(set,fq);
				    if(o_cnt) {
					atomic64_add((long long)skb->len, &o_cnt->bytes);
					atomic64_add((long long)1, &o_cnt->packets);
				    }
				    opt->ext.skbinfo.skbprio = fq->f_prio ? fq->prio:0;
				    opt->ext.skbinfo.skbmark = fq->f_mark ? fq->mark:0;
				    opt->ext.skbinfo.skbmarkmask = fq->f_mark ? fq->mask:0;
				} else {
				    opt->ext.skbinfo.skbprio = 0;
				    opt->ext.skbinfo.skbmark = 0;
				    opt->ext.skbinfo.skbmarkmask = ~0u;
				}
				return res;
			}
			return 0;
			}
	  case IPSET_ADD:
	  case IPSET_DEL:
			{
			tree_node_t rq;

			memset((char *)&rq,0,sizeof(rq));
			rq.mlen = map->masklen;
			rq.ip = ip & l2m[map->masklen];
			rq.f_tmo = map->timeout != 0;
			if (rq.f_tmo) {
				rq.expired = opt->ext.timeout;
				if(!rq.expired) rq.expired = map->timeout;
				rq.expired *= HZ;
				rq.expired += jiffies;
			}
			res = __addip(set,&rq,adt == IPSET_ADD, NULL, NULL);
			return res;
			}
		  break;
	  default: break;
	}
	return -IPSET_ERR_PROTOCOL;
}

/********************************************************************/

static int
ipcidr_uadt(struct ip_set *set, struct nlattr *tb[],
               enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	struct ip_set_ipcidr *map = set->data;
	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
	struct one_string *o_str = NULL;
	struct ip_set_counter o_cnt;
	char *str = NULL;
	size_t str_len = 0;

	u32 ip=0, ip_to=0, masklen=0;
	u32 timeout = 0;
	tree_node_t rq;
	int ret = 0;

	if(!set) return -IPSET_ERR_PROTOCOL;
	if (unlikely(!tb[IPSET_ATTR_IP])) return -IPSET_ERR_PROTOCOL;
	if (unlikely(!ip_set_optattr_netorder(tb, IPSET_ATTR_SKBMARK)))
			return -IPSET_ERR_PROTOCOL;
	if (tb[IPSET_ATTR_CIDR] &&
	    tb[IPSET_ATTR_IP_TO] ) return -IPSET_ERR_TYPE_MISMATCH;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	memset((char *)&rq,0,sizeof(rq));
	memset((char *)&o_cnt,0,sizeof(o_cnt));

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip);
	if (ret) return ret;

	if (tb[IPSET_ATTR_CIDR]) {
		masklen = nla_get_u8(tb[IPSET_ATTR_CIDR]);
		if(masklen > 32) masklen = 32;
		if(map->masklen && masklen > map->masklen) masklen = map->masklen;
	} else masklen = map->masklen;

	if(masklen)
		ip &= l2m[masklen];
	rq.ip = ip;
	rq.mlen = masklen;

	if(tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret) return ret;
		if(masklen)
			ip_to &= l2m[masklen];
	}
        ret = ip_set_get_extensions(set, tb, &ext);
        if (ret) return ret;

	timeout = tb[IPSET_ATTR_TIMEOUT] ? ext.timeout : map->timeout;
	rq.f_tmo = timeout > 0 ? 1:0;
	rq.expired = rq.f_tmo ? timeout*HZ + jiffies:0;

	if (tb[IPSET_ATTR_BYTES] || tb[IPSET_ATTR_PACKETS]) {
		if (!SET_WITH_COUNTER(set))
		    return -IPSET_ERR_COUNTER;
		if (tb[IPSET_ATTR_BYTES])
		    ext.bytes = be64_to_cpu(nla_get_be64(tb[IPSET_ATTR_BYTES]));
		if (tb[IPSET_ATTR_PACKETS])
		    ext.packets = be64_to_cpu(nla_get_be64(tb[IPSET_ATTR_PACKETS]));
		ip_set_update_counter(&o_cnt,&ext,0);
	}

	if(tb[IPSET_ATTR_COMMENT]) {
		if (!SET_WITH_COMMENT(set))
			return -IPSET_ERR_COUNTER;
		str = nla_data(tb[IPSET_ATTR_COMMENT]);
		if(!str || !*str) return -IPSET_ERR_PROTOCOL;
		str_len = strlen(str);

		o_str = find_one_string(map,str);
		if(o_str)
			atomic_inc(&o_str->ref);
		  else
			o_str = alloc_one_string(map,str);

		if(!o_str) return -ENOMEM;
	}
	if(tb[IPSET_ATTR_SKBMARK]) {
		rq.f_mark = 1;
		rq.mark = ext.skbinfo.skbmark;
		rq.mask = ext.skbinfo.skbmarkmask;
	}
	if(tb[IPSET_ATTR_SKBPRIO]) {
		rq.f_prio = 1;
		rq.prio = ext.skbinfo.skbprio;
	}
	rq.f_cnt = SET_WITH_COUNTER(set) ? 1:0;

	switch(adt) {
	  case IPSET_TEST:
			return  __testip(set,ip, NULL);
	  case IPSET_ADD:
	  case IPSET_DEL:
			{
			struct _netlist l[64];
			int rl;


			if(ip_to == 0 || ip_to == ip) {
				ret = __addip(set, &rq , adt == IPSET_ADD, o_str, &o_cnt);
				u_compress(set);
				return ret;
			}

			rl = r2l(ip,ip_to,l,sizeof(l)/sizeof(l[0]));
			while(rl) {
				--rl;
				rq.ip = l[rl].ip;
				rq.mlen = l[rl].masklen;
				ret = __addip(set, &rq, adt == IPSET_ADD, o_str, &o_cnt);
				if(ret) break;
			}
			u_compress(set);
			if(o_str) {
				spin_lock(&map->str_lock);
				free_one_string(o_str);
				spin_unlock(&map->str_lock);
			}
			return ret;
			}
	  default: break;
	}	
	return -IPSET_ERR_PROTOCOL;
}


static void __flush(struct ip_set_ipcidr *map)
{
	_compress(map->tree,1,map);
	map->tree = NULL;
}

static void ipcidr_destroy(struct ip_set *set)
{
	struct ip_set_ipcidr *map = (struct ip_set_ipcidr *) set->data;

	DP("destroy %s\n",set->name);
	__flush(map);
	free_one_str(map);
	kfree(map);
	set->data = NULL;
}

static void ipcidr_flush(struct ip_set *set)
{
	struct ip_set_ipcidr *map = (struct ip_set_ipcidr *) set->data;
	DP("flush %s\n",set->name);
	__flush(map);
}

static int ipcidr_head(struct ip_set *set, struct sk_buff *skb)
{
	struct ip_set_ipcidr *map = (struct ip_set_ipcidr *) set->data;
	struct nlattr *nested;

	DP("list_header %s %u %u\n",set->name,map->timeout,map->masklen);

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	nla_put_net32(skb, IPSET_ATTR_SIZE, htonl(map->node_count));
	if (map->masklen != 32)
		nla_put_u8(skb, IPSET_ATTR_NETMASK, (u8)map->masklen);
	if (map->timeout)
		nla_put_u32(skb, IPSET_ATTR_TIMEOUT, map->timeout);
	nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(set->ref));
	nla_put_net32(skb, IPSET_ATTR_CADT_FLAGS, htonl(map->flags));
	nla_put_net32(skb, IPSET_ATTR_MEMSIZE,htonl(map->node_count*set->dsize + total_one_str(map)));
	ipset_nest_end(skb, nested);
	return 0;
nla_put_failure:
	DP("%s %s fail\n",__func__,set->name);
	return -EMSGSIZE;
}
static inline int may_be_cidr(u32 ip1,u32 ip2) {
	u32 mlen,i;
	mlen = ip2 - ip1;
	for(i = 0; mlen && i < 32; i++) {
	        if(mlen & 1) {
	    	    mlen >>= 1;
	    	    return mlen ? 0:i;
	        }
	        mlen >>=1;
	}
	return 0;
}
static int ipcidr_put_node(tree_node_t *n,
		struct sk_buff *skb,const struct ip_set *set) {

	DBGDATA(char _ip1[20])
	DBGDATA(char _ip2[20])
	struct nlattr * nested;
	int res = 0;

	if(!n->f_act) return 0;
	n->f_act = 0;

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested) 
		return 1;
        do {
	if(nla_put_ipaddr4(skb, IPSET_ATTR_IP,htonl(n->ip)))
		break;
	if(n->l1) {
	    u32 *ip = (u32 *)&n->l0;
	    int i = may_be_cidr(n->ip,*ip);
	    DP("  put range  %s/%d - %s %s tmo %d:%d mark %d:%x may_be_cidr %d\n",
		__str_ip(n->ip,_ip1),n->mlen, __str_ip(*ip,_ip2),
		n->f_act ? "act" : "", n->f_act,
		n->f_act && n->f_tmo ? (unsigned int)n->expired:0,
		n->f_mark, n->f_mark ? n->mark:0, i);

	    if(i && (n->ip & (0xfffffffful << i)) == n->ip )
		res =nla_put_u8(skb, IPSET_ATTR_CIDR, 32-i);
	      else
	        res =nla_put_ipaddr4(skb, IPSET_ATTR_IP_TO,htonl(*ip - 1));
	    if(res) break;

	} else {
	    DP("  put cidr  %s/%d %s a:%d tmo %d:%d mark %d:%x/%x\n",
		__str_ip(n->ip,_ip1),n->mlen,
		n->f_act ? "act" : "", n->f_act,
		n->f_tmo, n->f_tmo ? (unsigned int)(n->expired-jiffies)/HZ:0,
		n->f_mark, n->f_mark ? n->mark:0,n->f_mark ? n->mask:0);
	    if(n->mlen != 32)
		if(nla_put_u8(skb, IPSET_ATTR_CIDR, n->mlen))
			break;
	}
	if(n->f_tmo && n->expired)
		if(nla_put_net32(skb, IPSET_ATTR_TIMEOUT,htonl((n->expired-jiffies)/HZ)))
				break;

	if(n->f_mark) {
		u64 fullmark = cpu_to_be64(( (u64)n->mark << 32 ) | (u64)n->mask);
		if(IPSET_NLA_PUT_NET64(skb, IPSET_ATTR_SKBMARK, fullmark,IPSET_ATTR_PAD))
				break;
	}
	if(n->f_prio) {
		if(nla_put_net32(skb, IPSET_ATTR_SKBPRIO, cpu_to_be32(n->prio)))
				break;
	}
	if(n->f_cnt) {
		struct ip_set_counter *n_cnt = get_counters(set,n);
		if(n_cnt)
			if(ip_set_put_counter(skb,n_cnt))
				break;
	}
	if (n->f_strlen) {
		struct one_string **n_str = get_comment(set,n);
		if(n_str && *n_str)
			if(nla_put_string(skb, IPSET_ATTR_COMMENT, &((*n_str)->str[0])))
				break;
	}
	ipset_nest_end(skb, nested);
	return 0;
	} while(0);

	DP(" nla_put_failure\n");
	nla_nest_cancel(skb, nested);
	return 1;
}

static void set_lastip_node(tree_node_t *p,const tree_node_t *n) {
DBGDATA(char _ip1[20])
DBGDATA(char _ip2[20])
  u32 *ip;
  size_t ns = sizeof(tree_node_t) + 
	  (n->f_cnt ? sizeof(struct ip_set_counter):0) +
	  (n->f_strlen ? sizeof(char *):0);
  memcpy(p,n,ns);
  p->l0 = NULL;
  p->l1 = NULL;
  ip = (u32 *)&p->l0;
  *ip = p->ip  + (1 << (32 - p->mlen));
  DP(" set start %s/%d end %s mark %u exp %lu\n",__str_ip(n->ip,_ip1),
		  n->mlen,__str_ip(*ip,_ip2),p->mark,p->expired);
}

static int seq_node(const tree_node_t *p,const tree_node_t *n) {
  u32 *ip;
  if(p->f_cnt || n->f_cnt) return 0;
  ip = (u32 *)&p->l0;
  return *ip == n->ip || (n->ip + (1 << (32 - n->mlen))) == p->ip ; 
}


static void add_node(tree_node_t *p, tree_node_t *n) {
DBGDATA(char _ip1[20])
DBGDATA(char _ip2[20])
  u32 *ip;
  ip = (u32 *)&p->l0;
  if(n->ip < p->ip) {
	p->ip = n->ip;
  } else {
  	*ip = n->ip + (1 << (32 - n->mlen));
  }
  p->l1  = (void *)1;
  DP(" add start %s end %s\n",__str_ip(p->ip,_ip1),__str_ip(*ip,_ip2));
}

static int _list_members(tree_node_t *n,
		struct sk_buff *skb,
		size_t *offset,
		tree_node_t *p,
		struct ip_set_ipcidr *map)
{
DBGDATA(char _ip1[20])
int res;

if(!n) return 0;

if(n->l0) { res = _list_members(n->l0,skb,offset,p,map); if(res) return res; }
if(n->l1) { res = _list_members(n->l1,skb,offset,p,map); if(res) return res; }


if(offset[0] >= offset[1]) {
    check_expires(n,jiffies, map);
    DP("  list %s/%d %s tmo %d:%d mark %d:%x/%x\n",
		__str_ip(n->ip,_ip1),n->mlen,n->f_act ? "act" : "",
		n->f_act,
		n->f_tmo ? (unsigned int)n->expired:0,
		n->f_mark, n->f_mark ? n->mark:0,n->f_mark ? n->mask:0 );
}

if(n->f_act ) {
	int ret;
	if(p->f_act) {
    		DP("  eq_node %d seq_node %d\n",eq_node(n,p,map->set),seq_node(p,n));
		if(eq_node(n,p,map->set) && seq_node(p,n)) {
		    add_node(p,n);
    		    DP("  add node\n");
		    return 0;
		}
		if(offset[0] >= offset[1]) {
			ret = ipcidr_put_node(p,skb,map->set);
			if(ret) return ret; // No mem in skb 
		}
		offset[0]++;
	}
	set_lastip_node(p,n);
}
return 0;
}

static int ipcidr_list(const struct ip_set *set,
		struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ip_set_ipcidr *map = (struct ip_set_ipcidr *) set->data;
	struct nlattr *atd;
	size_t offset[2]; // 0 - current, 1 - start
	/* p_buf - maximum node size */
	char p_buf[sizeof(tree_node_t) + sizeof(struct ip_set_counter) + sizeof(char*)];
	tree_node_t *p;
	int res;

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd) return -EMSGSIZE;
	DP("%s %s ipset_nest_start offs %ld\n",
			__func__,set->name,cb->args[IPSET_CB_ARG0]);
	offset[0] = 0;
	offset[1] = cb->args[IPSET_CB_ARG0];

	print_one_str(map);

	p = (tree_node_t *)p_buf;
	memset((char *)p_buf,0,sizeof(p_buf));
	res = _list_members(map->tree,skb,offset,p,map);
	if(!res && p->f_act && offset[0] >= offset[1]) {
		res = ipcidr_put_node(p,skb,set);
		if(!res) offset[0]++;
	}

	if(res && offset[0] <= offset[1]) {
		DP("%s %s EMSGSIZE offs %d\n",
			__func__,set->name,(int)offset[0]);
		cb->args[IPSET_CB_ARG0] = 0;
		return -EMSGSIZE;
	}

	DP("%s %s ipset_nest_end offs %d res %d\n",
			__func__,set->name,(int)offset[0],res);

	ipset_nest_end(skb, atd);
	cb->args[IPSET_CB_ARG0] = res ? offset[0] : 0;
	DP("%s %s return %s\n",__func__,
		set->name,res && offset[0] <= offset[1] ? "-EMSGSIZE":"OK");
	return res && offset[0] <= offset[1] ? -EMSGSIZE : 0;
}
static bool ipcidr_same_set(const struct ip_set *a, const struct ip_set *b)
{
	const struct ip_set_ipcidr *x = a->data;
	const struct ip_set_ipcidr *y = b->data;

	return x->timeout == y->timeout &&
		x->masklen == y->masklen &&
		x->mark == y->mark && x->mask == y->mask;
}

static const struct ip_set_type_variant ipcidr_op = {
	.kadt	= ipcidr_kadt,
	.uadt	= ipcidr_uadt,
	.adt	= { NULL, },
	.destroy = ipcidr_destroy,
	.flush	= ipcidr_flush,
	.head	= ipcidr_head,
	.list	= ipcidr_list,
	.same_set = ipcidr_same_set,
};

static int create(struct net *net, struct ip_set *set, struct nlattr *tb[], u32 flags)
{
	struct ip_set_ipcidr *map;
	unsigned int      timeout,masklen;

	if (!(set->family == AF_INET)) return -IPSET_ERR_INVALID_FAMILY;
	timeout = 0;
	if(tb[IPSET_ATTR_TIMEOUT]) {
		timeout = ntohl(nla_get_u32(tb[IPSET_ATTR_TIMEOUT]));
	}
	masklen = 32;
	if(tb[IPSET_ATTR_NETMASK]) {
		masklen = nla_get_u8(tb[IPSET_ATTR_NETMASK]);
	}

	map = kmalloc(sizeof(struct ip_set_ipcidr), GFP_KERNEL);
	if (!map) {
		DP("out of memory for %d bytes",
		   (int)sizeof(struct ip_set_ipcidr));
		return -ENOMEM;
	}
	memset(map, 0,sizeof( struct ip_set_ipcidr));
	map->timeout = timeout;
	map->masklen = masklen;
	if(!map->masklen || map->masklen > 32) map->masklen = 32;
	set->variant = &ipcidr_op;

	ip_set_elem_len(set, tb, 0, 0);

	set->dsize = sizeof(tree_node_t);
	if (SET_WITH_COUNTER(set))
		set->dsize += sizeof(struct ip_set_counter);
        if (SET_WITH_COMMENT(set)) 
		set->dsize += sizeof(char *);

        if (tb[IPSET_ATTR_CADT_FLAGS]) {
                map->flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);
        }
	DP("%s flags %u ext %x dsize %d, Masklen:%u timeout:%u\n",set->name,
		map->flags,set->extensions,(int)set->dsize, map->masklen, map->timeout);
	INIT_LIST_HEAD(&map->str);
	spin_lock_init(&map->str_lock);
	set->data = map;
	map->set = set;

	return 0;
}

static struct ip_set_type ipcidr_type __read_mostly = {
	.name		= "ipcidr",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP,
	.dimension	= IPSET_DIM_ONE,
	.family		= AF_INET,
	.revision_min	= 3,
	.revision_max	= 3,
	.create		= create,
	.create_policy	= {
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_NETMASK]	= { .type = NLA_U8  },
		[IPSET_ATTR_CADT_FLAGS] = { .type = NLA_U32 },
	},
	.adt_policy	= {
		[IPSET_ATTR_IP]		= { .type = NLA_NESTED },
		[IPSET_ATTR_IP_TO]	= { .type = NLA_NESTED },
		[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
		[IPSET_ATTR_SKBMARK]    = { .type = NLA_U64 },
		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
		[IPSET_ATTR_BYTES]      = { .type = NLA_U64 },
		[IPSET_ATTR_PACKETS]    = { .type = NLA_U64 },
		[IPSET_ATTR_COMMENT]    = { .type = NLA_NUL_STRING,
					    .len  = IPSET_MAX_COMMENT_SIZE },

	},
	.me		= THIS_MODULE,
};


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaliy Lavrov <lve@guap.ru>");
MODULE_DESCRIPTION("ipcidr type of IP sets");

static int __init init(void)
{
#if 0
	printk(KERN_INFO "Header size %d node_size %d\n",
		(int)sizeof( struct ip_set_ipcidr ), (int)sizeof( tree_node_t ));
#endif
	return ip_set_type_register(&ipcidr_type);
}

static void __exit fini(void)
{
	ip_set_type_unregister(&ipcidr_type);
}

module_init(init);
module_exit(fini);
