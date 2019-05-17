#ifndef __IP_SET_STRING_H
#define __IP_SET_STRING_H

#include <linux/netfilter/ipset/ip_set.h>

#define SETTYPE_NAME "string"

struct ip_set_req_string {
	char	str[IPSET_MAX_COMMENT_SIZE];
};

#endif	/* __IP_SET_STRING_H */
