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


/* Parse commandline arguments */
static const struct ipset_arg string_create_args[] = {
	{ },
};

static const struct ipset_arg string_add_args[] = {
	{ },
};

static const char string_usage[] =
"create SETNAME name\n"
"add    SETNAME name\n"
"del    SETNAME name\n"
"test   SETNAME name\n\n"
"where depending on the INET family\n"
"      string is ASCII string\n";

struct ipset_type ipset_string0 = {
	.name = "string",
	.alias = { "string", NULL },
	.revision = 3,
	.family = NFPROTO_IPSET_IPV46,
	.dimension = IPSET_DIM_ONE,
	.elem = {
		[IPSET_DIM_ONE - 1] = {
			.parse = ipset_parse_comment,
			.print = ipset_print_comment,
			.opt = IPSET_OPT_ADT_COMMENT
		},
	},
	.compat_parse_elem = ipset_parse_comment,
	.cmd =  {
		[IPSET_CREATE] = {
			.args = {
				IPSET_ARG_COUNTERS,
				IPSET_ARG_NONE
			},
			.need = 0,
			.full = 0,
			.help = "string",
		},
		[IPSET_ADD] = {
			.args = {
				IPSET_ARG_PACKETS,
				IPSET_ARG_BYTES,
				IPSET_ARG_NONE
			},
			.need = 0,
			.full = IPSET_FLAG(IPSET_OPT_ADT_COMMENT),
			.help = "string",
		},
		[IPSET_DEL] = {
			.args = {
				IPSET_ARG_NONE
			},
			.need = 0,
			.full = IPSET_FLAG(IPSET_OPT_ADT_COMMENT),
			.help = "string",
		},
		[IPSET_TEST] = {
			.args = {
				IPSET_ARG_NONE
			},
			.need = 0,
			.full = IPSET_FLAG(IPSET_OPT_ADT_COMMENT),
			.help = "string",
		},
				
	},
	.usage = "",
	.description = "Counter exttensions",
};

void _init(void);
void _init(void)
{
	ipset_type_add(&ipset_string0);
}

