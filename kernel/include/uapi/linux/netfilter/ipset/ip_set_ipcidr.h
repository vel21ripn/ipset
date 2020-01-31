#ifndef __IP_SET_IPCIDR_H
#define __IP_SET_IPCIDR_H

#include <linux/netfilter/ipset/ip_set.h>

#define SETTYPE_NAME "ipcidr"
#define MAX_RANGE 0x0000FFFF

struct _tree_node {
	u32		  ip;
	uint16_t	  mlen,f_tmo:1,f_act:1,f_mark:1;
	unsigned long	  expired;
	uint32_t	  mark,mask;
	struct _tree_node *l0,*l1;
};
typedef struct _tree_node tree_node_t;

struct ip_set_ipcidr {
	unsigned int	timeout;
	unsigned int	masklen;
	uint32_t	mark,mask;
	unsigned int	gc_interval;
#ifdef __KERNEL__
	struct ip_set	*set;
	struct timer_list gc;
	tree_node_t	*tree;
	int		node_count;
	uint32_t	flags;
#endif
};

struct ip_set_req_ipcidr_create {
	unsigned int timeout;
	unsigned int masklen;
};

struct ip_set_req_ipcidr {
	u32	 ip;
	unsigned int masklen;
	uint32_t mark,mask;
	unsigned int timeout;
	u32	  ip2;
	unsigned int f_tmo:1,f_act:1,f_excl:1,f_mark:1;
};

#endif	/* __IP_SET_CIDREE_H */
