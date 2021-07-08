/* Copyright (C)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

/* Kernel module implementing an IP set type: the string type */

#undef IP_SET_DEBUG
//#define IP_SET_DEBUG 1

#include <linux/version.h>

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>

#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>

#include <net/netlink.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_string.h>
#include "libahocorasick.h"
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 4, 0)
MODULE_IMPORT_NS(NET_IPSET);
#endif

#ifdef IP_SET_DEBUG
#undef DP
#define DP(fmt, args...) printk(fmt, ## args)
#define DBGDATA(a...) a;
//#warning  "DEBUG code"
#else
#define DP(fmt, args...)
#define DBGDATA(a...)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
#error "Only for >= 3.4.0"
#endif

struct one_string {
    struct one_string *next;
    size_t      len; // length of origin string
    size_t      hlen; // length of hex string
    char        *hstr;
    char        *str;
    char        data[0]; 
    /* counter ext + hex_string + '\0' +  string + '\0' */
};

typedef struct one_string one_string_t;

struct ip_set_string {
    int           count;
    int           minlen;
    spinlock_t    first_lock;
    spinlock_t    ac_lock;
    one_string_t  *first;
    AC_AUTOMATA_t __rcu *automata;
    uint32_t      flags,lc;
};

#ifdef IP_SET_DEBUG
static void ascii_str(const char *str,size_t len,char *buf,size_t buf_len) {
    int i;
    for(i=0; i < len && i < buf_len; i++) {
        buf[i] = (str[i] >= ' ' && str[i] <= 127) ? str[i]:'.';
    }
    buf[i] = 0;
}
#endif

static int hexchar2(const char *str,char *dest) {
    int r=0,i;
    char c;
    for(i=0; i < 2;i++) {
        c = *str++;
        r <<= 4;
        if(c >= '0' && c <= '9') {
            r |= c - '0';
        } else {
            if((c >= 'A' && c <= 'F') ||
               (c >= 'a' && c <= 'f')) {
                r |= (c & ~0x20)-'A'+10;
            } else return 0;
        }
    }
    *dest = r & 0xff;
    return 1;
}

static int parse_hex_string(const char *str,size_t len,char *dest) {
    int  hlen = 0;
    char c,hc;
    int  hex;
    unsigned int i;

    for(i=0,hex=0,hc=0; i < len; i++) {
        c = *str++;
        if(c == '\\') {
            if(i+1 < len) {
                if(dest) dest[hlen] = *str;
                hlen++;
                i++;
                str++;
                continue;
            }
            if(dest) dest[hlen] = c;
            hlen++;
            continue;
        }
        if( c == '|' ) {
            if(hex) {
                hex = 0;
                continue;
            }
            hex++;
            if(i+3 < len && hexchar2(str,&hc)) {
                if(dest) dest[hlen] = hc;
                hlen++;
                i += 2;
                str += 2;
                continue;
            }
            return -1; // invalid hex
        }
        if(hex) {
            if(i+2 < len && hexchar2(str-1,&hc)) {
                if(dest) dest[hlen] = hc;
                hlen++;
                i++;
                str++;
                continue;
            }
            return -1; // invalid hex
        }
        if(dest) dest[hlen] = c;
        hlen++;
    }
    if(dest) dest[hlen] = '\0';
    return hlen;
}

static void free_one_string(one_string_t *str) {
	kfree(str);
}

static one_string_t *alloc_one_string(const char *str,size_t len,int cext) {
    one_string_t *r;
    size_t hlen;
    int ofs;

    if(!len) return NULL;

    hlen = parse_hex_string(str,len,NULL);

    r = (one_string_t *)kmalloc(sizeof(one_string_t)+len+1+hlen+1 +
                    sizeof(struct ip_set_counter)*cext, GFP_ATOMIC);
    if(!r) return r;
    r->next = NULL;
    r->len = len;
    r->hlen = hlen;
    ofs = 0;
    if(cext) {
        ofs += sizeof(struct ip_set_counter);
        memset(r->data,0,sizeof(struct ip_set_counter));
    }
    r->hstr = &r->data[ofs];
    parse_hex_string(str,len,r->hstr);
    ofs += hlen+1;
    r->str = &r->data[ofs];
    memcpy(r->str,str,len+1);
    return r;
}

struct frag_array {
        void    *ptr;
        size_t  len;
};

struct acho_ret {
        struct ip_set *set;
        const struct ip_set_ext *ext;
        char *name;
        int len;
        int id;
        int exact;
};

#ifdef IP_SET_DEBUG
#define MATCH_DEBUG_INFO(fmt, ...) if(txt->debug) printk(fmt, ##__VA_ARGS__)
#else
#define MATCH_DEBUG_INFO(fmt, ...)
#endif
static int acho_match_mc(AC_MATCH_t *m, AC_TEXT_t *txt, void *match) {
  AC_PATTERN_t *pattern = m->patterns;
  struct acho_ret *p = (struct acho_ret *)match;
  int i,start,end = m->position;

  for(i=0; i < m->match_num; i++,pattern++) {
    /*
     * See ac_automata_exact_match()
     * The bit is set if the pattern exactly matches AND
     * the length of the pattern is longer than that of the previous one.
     * Skip shorter (less precise) templates.
     */
    if(!(m->match_mask & (1 << i)))
            continue;
    start = end - pattern->length;

    MATCH_DEBUG_INFO("[NDPI] Searching: [to search: %.*s/%u][pattern: %s%.*s%s/%u] %d-%d\n",
            txt->length, txt->astring,(unsigned int) txt->length,
            m->patterns[0].rep.from_start ? "^":"",
            (unsigned int) pattern->length, pattern->astring,
            m->patterns[0].rep.at_end ? "$":"", (unsigned int) pattern->length,
            start,end);

    p->id = m->patterns->rep.number;
    p->name = m->patterns->astring;
    p->len = m->patterns->length;
    if(start == 0 && end == txt->length && p->exact) return 1;

    if(p->set && p->ext) {
        struct ip_set_counter *counter = 
                (struct ip_set_counter *)(m->patterns->astring - sizeof(struct ip_set_counter));
        ip_set_update_counter(counter,p->ext,0);
    }
  }
  return 0;
}

static int acho_match_string0(AC_AUTOMATA_t *automa, 
                char *string_to_match,size_t len) {
  AC_TEXT_t ac_input_text;
  struct acho_ret match;

  if((automa == NULL) || (string_to_match == NULL) || (string_to_match[0] == '\0'))
    return 0;

  memset((char *)&match,0,sizeof(match));
  memset((char *)&ac_input_text,0,sizeof(ac_input_text));

  match.exact = 1;
  ac_input_text.astring = string_to_match, ac_input_text.length = len;

  ac_automata_search(automa, &ac_input_text, (void *)&match);
  return match.id > 0;
}

noinline static int acho_match_string(AC_AUTOMATA_t *automa, 
                struct frag_array *frag, size_t frag_num,
                struct ip_set *set, const struct ip_set_ext *ext) {
  AC_TEXT_t ac_input_text;
  struct acho_ret match;
  int i;

  if((automa == NULL) || (frag == NULL) || (frag[0].ptr == NULL) || (frag_num == 0))
    return 0;

  memset((char *)&match,0,sizeof(match));
  memset((char *)&ac_input_text,0,sizeof(ac_input_text));
  match.id = 0;

  if(set && ext) {
        match.set = set;
        match.ext = ext;
        for(i = 0; i < frag_num; i++) {
            ac_input_text.astring = frag[i].ptr, ac_input_text.length = frag[i].len;
            if(!frag[i].ptr || !frag[i].len) continue;
            ac_automata_search(automa, &ac_input_text, (void *)&match);
			ac_input_text.next_search = 1;
#ifdef IP_SET_DEBUG
	    if(frag[i].len < 256) {
        	char buf[256*2+2];
        	ascii_str(frag[i].ptr,frag[i].len,buf,sizeof(buf)-1);
        	DP("MATCH len %zu hstr '%s' ID %d\n",
            	frag[i].len,buf,match.id);
	    }
#endif
        }
        return match.id;
  }
  for(i = 0; i < frag_num; i++) {
      ac_input_text.astring = frag[i].ptr, ac_input_text.length = frag[i].len;
      if(ac_automata_search(automa, &ac_input_text, (void *)&match))
              return 1;
	  ac_input_text.next_search = 1;
  }
  return 0;

}

/*********************************************************************************/

static void automata_release(struct rcu_head *head) {
		AC_AUTOMATA_t *tmp = container_of(head, AC_AUTOMATA_t, rcu);
        ac_automata_release(tmp,0);
}

static void acho_replace(struct ip_set_string *map, AC_AUTOMATA_t *automata) {
	AC_AUTOMATA_t *tmp;

    spin_lock_bh(&map->ac_lock);
    tmp = rcu_dereference_protected(map->automata,lockdep_is_held(&map->ac_lock));
    rcu_assign_pointer(map->automata, automata);
    spin_unlock_bh(&map->ac_lock);
    if(tmp)
        call_rcu(&tmp->rcu, automata_release);
}

static int acho_build(struct ip_set_string *map, int op, one_string_t *str) {
    AC_AUTOMATA_t *automata;
    one_string_t *n,*t,*p;
    AC_PATTERN_t ac_pattern;
    int r,minlen=0,d_ok = 0;

	automata = smp_load_acquire(&map->automata);
    r = automata ? acho_match_string0(automata,str->hstr,str->hlen) : 0;

#ifdef IP_SET_DEBUG
    {
        char buf[128];
        ascii_str(str->hstr,str->hlen,buf,sizeof(buf)-1);
        DP("%s '%s' len %zu hstr '%s' hlen:%zu match %d\n",
            op ? "ADD":"DEL",str->str,str->len, buf,str->hlen,r);
    }
#endif

    if(op) {
        if(r) return -IPSET_ERR_EXIST;
    } else {
        if(!r) return -IPSET_ERR_EXIST;
    }

    memset(&ac_pattern, 0, sizeof(ac_pattern));

    automata = ac_automata_init(acho_match_mc);
    if(!automata) return -ENOMEM;
	ac_automata_feature(automata,AC_FEATURE_NO_ROOT_RANGE | (map->lc ? AC_FEATURE_LC:0));
	spin_lock(&map->first_lock);

	for(p = NULL,n = map->first; n; n = t) {
		t = n->next;
        if(!op && str->len == n->len && !memcmp(str->str,n->str,n->len)) {
			if(p) {
				p->next = t;
//				if(cmpxchg(&p->next,n,t) != n) BUG_ON(1);
			} else {
				map->first = t;
//				if(cmpxchg(&map->first,n,t) != n) BUG_ON(1);
			}
            free_one_string(n);
            map->count--;
			d_ok++;
			BUG_ON(d_ok > 1);
            continue;
        }
        ac_pattern.astring = n->hstr;
        ac_pattern.length = n->hlen;
        ac_pattern.rep.number = 1;
        if(ac_automata_add(automata, &ac_pattern) != ACERR_SUCCESS) {
            ac_automata_release(automata,0);
            return -1;
        }
        if(minlen < n->hlen) minlen = n->hlen;
    	p = n;
    }
    if(op) {
        ac_pattern.astring = str->hstr;
        ac_pattern.length  = str->hlen;
        ac_pattern.rep.number = 1;
        if(ac_automata_add(automata, &ac_pattern) != ACERR_SUCCESS) {
            ac_automata_release(automata,0);
            return -1;
        }
        if(minlen < str->hlen) minlen = str->hlen;

	    str->next = map->first;
		map->first = str;

        map->count++;
    }
	spin_unlock(&map->first_lock);

	if(!op)
		free_one_string(str);

    ac_automata_finalize(automata);
	acho_replace(map,automata);
    map->minlen = minlen;

    return 0;
}

/********************************************************************/

static int
__teststr(struct ip_set *set, struct ip_set_string *map,
		const struct ip_set_ext *ext, 
		struct frag_array *frag, size_t frag_num, int unlocked)
{
AC_AUTOMATA_t * automata;
int r;

    if(!set) return 0;
    if(!map) return 0;

    if(!READ_ONCE(map->first)) return 0;
	rcu_read_lock();
	automata = rcu_dereference(map->automata);
	r = automata ? acho_match_string(automata,frag,frag_num,set,ext) : 0;
	rcu_read_unlock();
	
    return r > 0 ? 1:0;
}


/********************************************************************/

static int get_payload_offset(const void *data,unsigned int data_len) {

    const struct iphdr *ip = (struct iphdr *)data;

    if(ip->version == 4) {
        unsigned int s_offset,pkt_len;
        if(data_len < sizeof(struct iphdr)) return 0;

        pkt_len = htons(ip->tot_len);
		if(pkt_len > data_len)
			return 0;
        s_offset = ip->ihl * 4;
		switch(ip->protocol) {
		case IPPROTO_TCP:
			{
			  const struct tcphdr *th = (struct tcphdr *)(data + s_offset);
              if(s_offset + sizeof(struct tcphdr) > data_len) return 0;

              s_offset += th->doff * 4;
			  if(0 && s_offset > data_len) {
				  printk("%s: tcp bug! offs %u data_len %u pkt_len %u ihl %u, doff %u\n",
						__func__, s_offset, data_len, pkt_len, ip->ihl, th->doff);
			  }
			}
			break;
		case IPPROTO_UDP:
            s_offset += sizeof(struct udphdr);
			break;
		case IPPROTO_ICMP:
            s_offset += sizeof(struct icmphdr);
		}
        return s_offset > data_len ? 0:s_offset;
    }
    return 0; // FIXME ipv6
}

static int
string_kadt(struct ip_set *set, const struct sk_buff *skb,
        const struct xt_action_param *par,
        enum ipset_adt adt,
        struct ip_set_adt_opt *opt)
{
    struct ip_set_string *map;
    struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
    const struct iphdr *ip;
    unsigned int s_offset,pkt_len;
    int res;

    if(!set) return -IPSET_ERR_PROTOCOL;
    map = set->data;
    if(!map) return -EINVAL;
    if(adt != IPSET_TEST) return -IPSET_ERR_PROTOCOL;

    ip = (struct iphdr *)skb_network_header(skb);
    if(!ip) return 0;

    if(!skb_is_nonlinear(skb)) {
        struct frag_array frag;
        pkt_len = skb->len;
        s_offset = get_payload_offset(ip,pkt_len);
		if(s_offset > pkt_len)
				return 0;
        frag.ptr = (char *)ip + s_offset;
        frag.len = pkt_len - s_offset;
        DP("__teststr %s linear len %zu\n",set->name,frag.len);
        res =  __teststr(set, map, &ext, &frag, 1 ,1);
    } else {
        struct frag_array frags[MAX_SKB_FRAGS+1];
        skb_frag_t *frag;
        int i,o,f;

        pkt_len = skb_headlen(skb);
        s_offset = get_payload_offset(ip,pkt_len);
		if(s_offset > pkt_len)
				return 0;
        o = 0;
        if(s_offset < pkt_len) {
            frags[o].ptr = (char *)ip + s_offset;
            frags[o].len = pkt_len - s_offset;
            o++;
            DP("__teststr %s nonlinear skb header %zu\n",set->name,frags[o].len);
        } else {
            DP("__teststr %s nonlinear skb header empty\n",set->name);
        }
        f = skb_shinfo(skb)->nr_frags;
        for (i = 0; i < f; i++) {
            frag = &skb_shinfo(skb)->frags[i];
            frags[o].ptr = skb_frag_address_safe(frag);
            frags[o].len = skb_frag_size(frag);
            DP("__teststr %s nonlinear skb frag:%d %zu\n",set->name,i,frags[o].len);
            o++;
        }
        DP("__teststr %s nonlinear frags %d\n",set->name,o);
        res =  __teststr(set, map, &ext, frags, o ,1);
    }

    return res >= 0 ? res : 0;
}


static int
string_uadt(struct ip_set *set, struct nlattr *tb[],
               enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
    struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
    struct ip_set_string *map;
    one_string_t *s;
    char *str = NULL;
    size_t len;
    int r;

    if (!set) return -IPSET_ERR_PROTOCOL;
    map = (struct ip_set_string *)set->data;
    if (!map) return -IPSET_ERR_PROTOCOL;
    if (unlikely(!tb[IPSET_ATTR_COMMENT])) return -IPSET_ERR_PROTOCOL;

    if (tb[IPSET_ATTR_LINENO])
        *lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

    if (tb[IPSET_ATTR_BYTES] || tb[IPSET_ATTR_PACKETS]) {
        if (!SET_WITH_COUNTER(set))
            return -IPSET_ERR_COUNTER;
        if (tb[IPSET_ATTR_BYTES])
            ext.bytes = be64_to_cpu(nla_get_be64(tb[IPSET_ATTR_BYTES]));
        if (tb[IPSET_ATTR_PACKETS])
            ext.packets = be64_to_cpu(nla_get_be64(tb[IPSET_ATTR_PACKETS]));
    }

    str = nla_data(tb[IPSET_ATTR_COMMENT]);
    if(!str || !*str) return -IPSET_ERR_PROTOCOL;
    len = strlen(str);
    
    s = alloc_one_string(str, len, SET_WITH_COUNTER(set) ? 1:0);
    if(!s) return -ENOMEM;
    if(SET_WITH_COUNTER(set))
        ip_set_init_counter((struct ip_set_counter *)&s->data[0], &ext);

    switch(adt) {
      case IPSET_TEST:
              {
                struct frag_array frag;
                frag.ptr = s->hstr;
                frag.len = s->hlen;
                r = __teststr(set,map, NULL, &frag, 1, 0);
				free_one_string(s);
                return r;
              }
      case IPSET_ADD:
      case IPSET_DEL:
                r = acho_build(map,adt == IPSET_ADD,s);
                if(r)
					free_one_string(s);
                return r;
      default: break;
    }   
    return -IPSET_ERR_PROTOCOL;
}


static void __flush(struct ip_set_string *map) {
    struct one_string *s,*n;

	acho_replace(map,NULL);
    map->minlen = 65536;

	spin_lock(&map->first_lock);
	s = xchg(&map->first,NULL);
	spin_unlock(&map->first_lock);

    for(n = NULL; s ; s = n) {
        n = s->next;
		free_one_string(s);
    }
    map->count = 0;
}

static void string_destroy(struct ip_set *set)
{
    struct ip_set_string *map = (struct ip_set_string *) set->data;

    DP("destroy %s\n",set->name);
    __flush(map);
    kfree(map);
    set->data = NULL;
}

static void string_flush(struct ip_set *set)
{
    struct ip_set_string *map = (struct ip_set_string *) set->data;
    DP("flush %s\n",set->name);
    __flush(map);
}

static int string_head(struct ip_set *set, struct sk_buff *skb)
{
    struct ip_set_string *map = (struct ip_set_string *) set->data;
    struct nlattr *nested;

    DP("list_header %s\n",set->name);

    nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
    if (!nested)
        goto nla_put_failure;
    nla_put_net32(skb, IPSET_ATTR_SIZE, htonl(map->count));
    nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(set->ref));
    nla_put_net32(skb, IPSET_ATTR_CADT_FLAGS, htonl(map->flags));
    nla_put_net32(skb, IPSET_ATTR_MEMSIZE,htonl(map->count));
    ipset_nest_end(skb, nested);
    return 0;

nla_put_failure:
    DP("%s %s fail\n",__func__,set->name);
    return -EMSGSIZE;
}

static int string_put_node(const struct ip_set *set,
            one_string_t *n,struct sk_buff *skb) {

    struct nlattr *nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
    if (!nested) 
        return 1;
    do {
        DP("%s %s l:%zu h:%zu s:%*s\n",__func__, set->name,
                        n->len,n->hlen,(int)n->len,n->str);
        if(nla_put_string(skb, IPSET_ATTR_COMMENT, n->str)) break;
        if (SET_WITH_COUNTER(set)) {
            if(ip_set_put_counter(skb,(struct ip_set_counter *)n->data)) break;
        }
        ipset_nest_end(skb, nested);
        return 0;
    } while(0);

    nla_nest_cancel(skb, nested);
    return 1;
}

static int _list_members(const struct ip_set *set, one_string_t *n,
        struct sk_buff *skb,
        size_t *offset)
{
	one_string_t *t;
    for(; n ; n = t) {
		t = READ_ONCE(n->next);
        if(offset[0] >= offset[1]) { 
            int ret = string_put_node(set, n, skb); 
            if(ret) return ret; // No mem in skb  
        } 
        offset[0]++;
    }
    return 0;
}

static int string_list(const struct ip_set *set,
        struct sk_buff *skb, struct netlink_callback *cb)
{
    struct ip_set_string *map = (struct ip_set_string *) set->data;
    struct nlattr *atd;
    size_t offset[2]; // 0 - current, 1 - start
    int res;

    atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
    if (!atd) return -EMSGSIZE;
    DP("%s %s ipset_nest_start offs %ld\n",
            __func__,set->name,cb->args[IPSET_CB_ARG0]);
    offset[0] = 0;
    offset[1] = cb->args[IPSET_CB_ARG0];

	spin_lock(&map->first_lock);
    res = _list_members(set, map->first,skb,offset);
	spin_unlock(&map->first_lock);

    if(res && offset[0] <= offset[1]) {
        DP("%s %s EMSGSIZE offs %d\n", __func__,set->name,(int)offset[0]);
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

static const struct ip_set_type_variant string_op = {
    .kadt   = string_kadt,
    .uadt   = string_uadt,
    .adt    = { NULL, },
    .destroy = string_destroy,
    .flush  = string_flush,
    .head   = string_head,
    .list   = string_list,
};

static int _create(struct net *net, struct ip_set *set, struct nlattr *tb[], u32 flags,int lc)
{
    struct ip_set_string *map;

    if (!(set->family == AF_INET)) return -IPSET_ERR_INVALID_FAMILY;

    map = kmalloc(sizeof(struct ip_set_string), GFP_KERNEL);
    if (!map) {
        DP("out of memory for %zu bytes", sizeof(struct ip_set_string));
        return -ENOMEM;
    }
    memset(map, 0,sizeof( struct ip_set_string));

    if (tb[IPSET_ATTR_CADT_FLAGS]) {
        map->flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);
    }

    DP("create set %s string flags %u ext %x\n",set->name,map->flags,flags);

    rcu_assign_pointer(map->automata, NULL);
    map->count = 0;
    map->minlen = 0;
    map->lc = lc;

    spin_lock_init(&map->first_lock);
    spin_lock_init(&map->ac_lock);

    set->data = map;
    set->variant = &string_op;
    set->dsize = ip_set_elem_len(set, tb,
                    sizeof(one_string_t),
                    __alignof__(sizeof(one_string_t)));
    return 0;
}
static int create(struct net *net, struct ip_set *set, struct nlattr *tb[], u32 flags) {
	return _create(net,set,tb,flags,0);
}
static int create_lc(struct net *net, struct ip_set *set, struct nlattr *tb[], u32 flags) {
	return _create(net,set,tb,flags,1);
}


static struct ip_set_type string_type __read_mostly = {
    .name       = "string",
    .protocol   = IPSET_PROTOCOL,
    .features   = IPSET_TYPE_NAME,
    .dimension  = IPSET_DIM_ONE,
    .family         = NFPROTO_UNSPEC,
    .revision_min   = 3,
    .revision_max   = 3,
    .create     = create,
    .create_policy  = {
        [IPSET_ATTR_CADT_FLAGS] = { .type = NLA_U32 },
    },
    .adt_policy = {
        [IPSET_ATTR_COMMENT]    = { .type = NLA_NUL_STRING,
                                    .len  = IPSET_MAX_COMMENT_SIZE },
        [IPSET_ATTR_BYTES]      = { .type = NLA_U64 },
        [IPSET_ATTR_PACKETS]    = { .type = NLA_U64 },

        [IPSET_ATTR_LINENO]     = { .type = NLA_U32 },
    },
    .me     = THIS_MODULE,
};
static struct ip_set_type string_type_lc __read_mostly = {
    .name       = "string_lc",
    .protocol   = IPSET_PROTOCOL,
    .features   = IPSET_TYPE_NAME,
    .dimension  = IPSET_DIM_ONE,
    .family         = NFPROTO_UNSPEC,
    .revision_min   = 3,
    .revision_max   = 3,
    .create     = create_lc,
    .create_policy  = {
        [IPSET_ATTR_CADT_FLAGS] = { .type = NLA_U32 },
    },
    .adt_policy = {
        [IPSET_ATTR_COMMENT]    = { .type = NLA_NUL_STRING,
                                    .len  = IPSET_MAX_COMMENT_SIZE },
        [IPSET_ATTR_BYTES]      = { .type = NLA_U64 },
        [IPSET_ATTR_PACKETS]    = { .type = NLA_U64 },

        [IPSET_ATTR_LINENO]     = { .type = NLA_U32 },
    },
    .me     = THIS_MODULE,
};



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaliy Lavrov <lve@guap.ru>");
MODULE_DESCRIPTION("string type of IP sets");

static int __init init(void)
{
    int r = ip_set_type_register(&string_type);
	if(r) return r;
    return ip_set_type_register(&string_type_lc);
}

static void __exit fini(void)
{
    ip_set_type_unregister(&string_type_lc);
    ip_set_type_unregister(&string_type);
}

module_init(init);
module_exit(fini);

/* vim: set ts=4 sw=4:  */

