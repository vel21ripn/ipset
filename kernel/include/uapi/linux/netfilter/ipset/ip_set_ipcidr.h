#ifndef __IP_SET_IPCIDR_H
#define __IP_SET_IPCIDR_H

#include <linux/netfilter/ipset/ip_set.h>

#define SETTYPE_NAME "ipcidr"
#define MAX_RANGE 0x0000FFFF

struct _tree_node {
	struct _tree_node *l0,*l1;
	uint32_t	  mark,mask;
	unsigned long	  expired;
	u32		  ip;
	uint16_t	  mlen;
	uint8_t		  f_strlen,f_tmo:1,f_act:1,f_mark:1,f_cnt:1;
	/* struct ip_set_counter */
	/* *(struct one_string) */
};
typedef struct _tree_node tree_node_t;

struct ip_set_ipcidr {
	unsigned int	timeout;
	unsigned int	masklen;
	uint32_t	mark,mask;
	unsigned int	gc_interval;
#ifdef __KERNEL__
	uint32_t	flags;
	struct ip_set	*set;
	tree_node_t	*tree;
	struct timer_list gc;
	struct list_head str;
	spinlock_t	str_lock;
	int		node_count;
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
	unsigned int f_tmo:1,f_act:1,f_excl:1,f_mark:1,f_string;
	char	 str[IPSET_MAX_COMMENT_SIZE];
};

#endif	/* __IP_SET_CIDREE_H */
