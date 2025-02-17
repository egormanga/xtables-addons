/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#pragma once

#include <linux/netfilter.h>

struct xt_xtee_tginfo {
	union nf_inet_addr gw;
	char oif[16];
	char iif[16];

	/* used internally by the kernel */
	struct xt_xtee_priv *priv __attribute__((aligned(8)));
};
