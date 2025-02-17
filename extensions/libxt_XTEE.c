/*
 *	"XTEE" target extension for iptables
 *      Patched by Egor Vorontsov <sdoregor@sdore.me>
 *      to support `iif', based on "TEE" target.
 *
 *	Copyright © Sebastian Claßen <sebastian.classen [at] freenet.ag>, 2007
 *	Jan Engelhardt <jengelh [at] medozas de>, 2007 - 2010
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <sys/socket.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include "xt_XTEE.h"
#include "compat_user.h"

enum {
	F_GATEWAY = 1 << 0,
	F_OIF     = 1 << 1,
	F_IIF     = 1 << 2,
};

static const struct option xtee_tg_opts[] = {
	{.name = "gateway", .has_arg = true, .val = 'g'},
	{.name = "oif",     .has_arg = true, .val = 'o'},
	{.name = "iif",     .has_arg = true, .val = 'i'},
	{NULL},
};

static void xtee_tg_help(void)
{
	printf(
"XTEE target options:\n"
"  --gateway IPADDR    Route packet via the gateway given by address\n"
"  --oif NAME          Include oif in route calculation\n"
"  --iif NAME          Change the packet's incoming interface to iif\n"
"\n");
}

static int xtee_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
	struct xt_xtee_tginfo *info = (void *)(*target)->data;
	const struct in_addr *ia;

	switch (c) {
	case 'g':
		if (*flags & F_GATEWAY)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify --gateway more than once");

		ia = xtables_numeric_to_ipaddr(optarg);
		if (ia == NULL)
			xtables_error(PARAMETER_PROBLEM,
			           "Invalid IP address %s", optarg);

		memcpy(&info->gw, ia, sizeof(*ia));
		*flags |= F_GATEWAY;
		return true;
	case 'o':
		if (*flags & F_OIF)
			xtables_error(PARAMETER_PROBLEM,
				"Cannot specify --oif more than once");
		if (strlen(optarg) >= sizeof(info->oif))
			xtables_error(PARAMETER_PROBLEM,
				"oif name too long");
		strcpy(info->oif, optarg);
		*flags |= F_OIF;
		return true;
	case 'i':
		if (*flags & F_IIF)
			xtables_error(PARAMETER_PROBLEM,
				"Cannot specify --iif more than once");
		if (strlen(optarg) >= sizeof(info->iif))
			xtables_error(PARAMETER_PROBLEM,
				"iif name too long");
		strcpy(info->iif, optarg);
		*flags |= F_IIF;
		return true;
	}

	return false;
}

static int xtee_tg6_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_target **target)
{
	struct xt_xtee_tginfo *info = (void *)(*target)->data;
	const struct in6_addr *ia;

	switch (c) {
	case 'g':
		if (*flags & F_GATEWAY)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify --gateway more than once");

		ia = xtables_numeric_to_ip6addr(optarg);
		if (ia == NULL)
			xtables_error(PARAMETER_PROBLEM,
			           "Invalid IP address %s", optarg);

		memcpy(&info->gw, ia, sizeof(*ia));
		*flags |= F_GATEWAY;
		return true;
	case 'o':
		if (*flags & F_OIF)
			xtables_error(PARAMETER_PROBLEM,
				"Cannot specify --oif more than once");
		if (strlen(optarg) >= sizeof(info->oif))
			xtables_error(PARAMETER_PROBLEM,
				"oif name too long");
		strcpy(info->oif, optarg);
		*flags |= F_OIF;
		return true;
	case 'i':
		if (*flags & F_IIF)
			xtables_error(PARAMETER_PROBLEM,
				"Cannot specify --iif more than once");
		if (strlen(optarg) >= sizeof(info->iif))
			xtables_error(PARAMETER_PROBLEM,
				"iif name too long");
		strcpy(info->iif, optarg);
		*flags |= F_IIF;
		return true;
	}

	return false;
}

static void xtee_tg_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "XTEE target: "
		           "--gateway or --iif parameter required");
}

static void xtee_tg_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct xt_xtee_tginfo *info = (const void *)target->data;

	if (numeric)
		printf(" XTEE gw:%s", xtables_ipaddr_to_numeric(&info->gw.in));
	else
		printf(" XTEE gw:%s", xtables_ipaddr_to_anyname(&info->gw.in));
	if (*info->oif != '\0')
		printf(" oif=%s", info->oif);
	if (*info->iif != '\0')
		printf(" iif=%s", info->iif);
}

static void xtee_tg6_print(const void *ip, const struct xt_entry_target *target,
                          int numeric)
{
	const struct xt_xtee_tginfo *info = (const void *)target->data;

	if (numeric)
		printf(" XTEE gw:%s", xtables_ip6addr_to_numeric(&info->gw.in6));
	else
		printf(" XTEE gw:%s", xtables_ip6addr_to_anyname(&info->gw.in6));
	if (*info->oif != '\0')
		printf(" oif=%s", info->oif);
	if (*info->iif != '\0')
		printf(" iif=%s", info->iif);
}

static void xtee_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_xtee_tginfo *info = (const void *)target->data;

	if (info->gw.ip)
		printf(" --gateway %s", xtables_ipaddr_to_numeric(&info->gw.in));
	if (*info->oif != '\0')
		printf(" --oif %s", info->oif);
	if (*info->iif != '\0')
		printf(" --iif %s", info->iif);
}

static void xtee_tg6_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_xtee_tginfo *info = (const void *)target->data;

	if (info->gw.ip6[0] || info->gw.ip6[1] || info->gw.ip6[2] || info->gw.ip6[3])
		printf(" --gateway %s", xtables_ip6addr_to_numeric(&info->gw.in6));
	if (*info->oif != '\0')
		printf(" --oif %s", info->oif);
	if (*info->iif != '\0')
		printf(" --iif %s", info->iif);
}

static struct xtables_target xtee_tg_reg = {
	.name          = "XTEE",
	.version       = XTABLES_VERSION,
	.revision      = 1,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_xtee_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_xtee_tginfo)),
	.help          = xtee_tg_help,
	.parse         = xtee_tg_parse,
	.final_check   = xtee_tg_check,
	.print         = xtee_tg_print,
	.save          = xtee_tg_save,
	.extra_opts    = xtee_tg_opts,
};

static struct xtables_target xtee_tg6_reg = {
	.name          = "XTEE",
	.version       = XTABLES_VERSION,
	.revision      = 1,
	.family        = NFPROTO_IPV6,
	.size          = XT_ALIGN(sizeof(struct xt_xtee_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_xtee_tginfo)),
	.help          = xtee_tg_help,
	.parse         = xtee_tg6_parse,
	.final_check   = xtee_tg_check,
	.print         = xtee_tg6_print,
	.save          = xtee_tg6_save,
	.extra_opts    = xtee_tg_opts,
};

static __attribute__((constructor)) void xtee_mt_ldr(void)
{
	xtables_register_target(&xtee_tg_reg);
	xtables_register_target(&xtee_tg6_reg);
}
