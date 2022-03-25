/* Shared library add-on to iptables for the TCP window target
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "../kernel/ipt_TBODY.h"

static const struct xt_option_entry TBODY_opts[] = {
	{.name = "tcpbodylen-set", .type = XTTYPE_UINT16, .id = 1,
	 .excl = 0, .flags = XTOPT_PUT, XTOPT_POINTER(struct ipt_TBODY_info, bodylen)},
    XTOPT_TABLEEND,
};

static void TBODY_help(void)
{
	printf("TCP window target options\n"
		"  --tcpbodylen-set value		    Force set tcp body length\n"
    );
}

static void TBODY_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void TBODY_check(struct xt_fcheck_call *cb)
{
}

static void TBODY_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_TBODY_info *info = 
		(struct ipt_TBODY_info *) target->data;
	printf(" --tcpbodylen-set %u", info->bodylen);
}

static void TBODY_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct ipt_TBODY_info *info =
		(struct ipt_TBODY_info *) target->data;
	printf(" TCP ACK body length set to %u", info->bodylen);
}

static struct xtables_target tbody_tg_reg = {
	.name		= "TCPBODY",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_TBODY_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_TBODY_info)),
	.help		= TBODY_help,
	.print		= TBODY_print,
	.save		= TBODY_save,
	.x6_parse	= TBODY_parse,
	.x6_fcheck	= TBODY_check,
	.x6_options	= TBODY_opts,
};

void _init(void)
{
	xtables_register_target(&tbody_tg_reg);
}
