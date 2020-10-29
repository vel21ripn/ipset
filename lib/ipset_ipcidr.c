/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libipset/data.h>			/* IPSET_OPT_* */
#include <libipset/parse.h>			/* parser functions */
#include <libipset/print.h>			/* printing functions */
#include <libipset/types.h>			/* prototypes */
#include <libipset/session.h>

/**
 * ipset_parse_ipcidr - parse IPv4 address, timeout, mark
 * @session: session structure
 * @opt: option kind of the data
 * @str: string to parse
 *
 * Compatibility parser.
 * IP[,Txxx][,Mxxx]
 *
 * Returns 0 on success or a negative error code.
 */

#define syntax_err(fmt, args...) \
	        ipset_err(session, "Syntax error: " fmt , ## args)

int
ipset_parse_ipcidr(struct ipset_session *session,
		      enum ipset_opt opt, const char *str);
int
ipset_parse_ipcidr(struct ipset_session *session,
		      enum ipset_opt opt, const char *str)
{
	char *tmp, *saved, *a;
	int err;
	uint8_t family = AF_INET;
	struct ipset_data *data;

	assert(session);
	assert(opt == IPSET_OPT_IP);
	assert(str);

	data = ipset_session_data(session);
	ipset_data_set(data, opt, &family);

	tmp = saved = strdup(str);
	if (saved == NULL)
		return ipset_err(session,
				 "Cannot allocate memory to duplicate %s.",
				 str);

	a = strchr(tmp,',');
	if (a)
		*a++ = '\0';

	err = ipset_parse_ip(session, opt, tmp);
	if (err) goto out;
	while(a) {
		tmp = strchr(a,',');
		if(tmp) *tmp++ = '\0';

		if(*a == 'T') {
			if (ipset_data_flags_test(ipset_session_data(session),
						  IPSET_FLAG(IPSET_OPT_TIMEOUT)))
				return syntax_err("mixed syntax, timeout already specified");
			err = ipset_parse_uint32(session, IPSET_OPT_TIMEOUT, a+1);
			if(err) break;

		} else if(*a == 'M') {
			if (ipset_data_flags_test(ipset_session_data(session),
						  IPSET_FLAG(IPSET_OPT_SKBMARK)))
				return syntax_err("mixed syntax, mark already specified");
			err = ipset_parse_skbmark(session, IPSET_OPT_SKBMARK, a+1);
			if(err) break;
		} else {
			free(saved);
			return syntax_err("invalid format");
		}
		a = tmp;
	}

out:
	free(saved);
	return err;
}


/* Parse commandline arguments */
static const struct ipset_arg ipcidr_create_args[] = {
	{ .name = { "family", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_FAMILY,
	  .parse = ipset_parse_family,		.print = ipset_print_family,
	},
	/* Alias: family inet */
	{ .name = { "-4", NULL },
	  .has_arg = IPSET_NO_ARG,		.opt = IPSET_OPT_FAMILY,
	  .parse = ipset_parse_family,
	},
	{ .name = { "netmask", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_NETMASK,
	  .parse = ipset_parse_netmask,		.print = ipset_print_number,
	},
	{ .name = { "timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ .name = { "skbinfo", NULL },
	  .has_arg = IPSET_NO_ARG,		.opt = IPSET_OPT_SKBINFO,
	  .parse = ipset_parse_flag,		.print = ipset_print_flag,
	},
	{ .name = { "comments", NULL },
	  .has_arg = IPSET_NO_ARG,		.opt = IPSET_OPT_CREATE_COMMENT,
	  .parse = ipset_parse_flag,		.print = ipset_print_flag,
	},
	{ .name = { "counters", NULL },
	  .has_arg = IPSET_NO_ARG,		.opt = IPSET_OPT_COUNTERS,
	  .parse = ipset_parse_flag,		.print = ipset_print_flag,
	},
	{ },
};

static const struct ipset_arg ipcidr_add_args[] = {
	{ .name = { "timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_timeout,		.print = ipset_print_number,
	},
	{ .name = { "skbmark", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,       .opt = IPSET_OPT_SKBMARK,
	  .parse = ipset_parse_skbmark,         .print = ipset_print_skbmark,
	},
	{ .name = { "comments", NULL },
	  .has_arg = IPSET_NO_ARG,		.opt = IPSET_OPT_ADT_COMMENT,
	  .parse = ipset_parse_flag,		.print = ipset_print_flag,
	},
	{ .name = { "counters", NULL },
	  .has_arg = IPSET_NO_ARG,		.opt = IPSET_OPT_COUNTERS,
	  .parse = ipset_parse_flag,		.print = ipset_print_flag,
	},
	{ },
};

static const char ipcidr_usage[] =
"create SETNAME ipcidr\n"
"               [netmask CIDR] [timeout VALUE] [mark VALUE]\n"
"add    SETNAME IP [timeout VALUE] [mark VALUE]\n"
"del    SETNAME IP\n"
"test   SETNAME IP [mark VALUE]\n\n"
"where depending on the INET family\n"
"      IP is a valid IPv4,\n"
"      CIDR is a valid IPv4 CIDR prefix.\n"
"      Adding/deleting multiple elements in IP/CIDR or FROM-TO form\n"
"      is supported for IPv4.\n";

struct ipset_type ipset_ipcidr0 = {
	.name = "ipcidr",
	.alias = { "ip4cidr", NULL },
	.revision = 3,
	.family = NFPROTO_IPV4,
	.dimension = IPSET_DIM_ONE,
	.elem = {
		[IPSET_DIM_ONE - 1] = {
			.parse = ipset_parse_ipcidr,
			.print = ipset_print_ip,
			.opt = IPSET_OPT_IP
		},
	},
	.compat_parse_elem = ipset_parse_ipcidr,
	.cmd =  {
		[IPSET_CREATE] = {
			.args = {
				IPSET_ARG_NETMASK,
				IPSET_ARG_TIMEOUT,
				IPSET_ARG_SKBINFO,
				IPSET_ARG_COUNTERS,
				IPSET_ARG_COMMENT,
				IPSET_ARG_NONE
			},
			.need = 0,
			.full = 0,
			.help = "[--netmask N] [--timeout N] [--skbinfo] [--counters] [--comments]",
		},
		[IPSET_ADD] = {
			.args = {
				IPSET_ARG_TIMEOUT,
				IPSET_ARG_SKBMARK,
				IPSET_ARG_ADT_COMMENT,
				IPSET_ARG_PACKETS,
				IPSET_ARG_BYTES,
				IPSET_ARG_NONE
			},
			.need = IPSET_FLAG(IPSET_OPT_IP),
			.full = IPSET_FLAG(IPSET_OPT_IP)
				| IPSET_FLAG(IPSET_OPT_IP_TO),
			.help = "IP[/MASK|-IP]",
		},
		[IPSET_DEL] = {
			.args = {
				IPSET_ARG_NONE
			},
			.need = IPSET_FLAG(IPSET_OPT_IP),
			.full = IPSET_FLAG(IPSET_OPT_IP)
				| IPSET_FLAG(IPSET_OPT_IP_TO),
			.help = "IP[/MASK|-IP]",
		},
		[IPSET_TEST] = {
			.args = {
				IPSET_ARG_NONE
			},
			.need = IPSET_FLAG(IPSET_OPT_IP),
			.full = IPSET_FLAG(IPSET_OPT_IP),
			.help = "IP",
		},
				
	},
	.usage = "Timeout and skbinfo support.",
	.description = "timeout, comment, counters, skbinfo support. IPv4 only.",
};

void _init(void);
void _init(void)
{
	ipset_type_add(&ipset_ipcidr0);
}

