// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	"XTEE" target extension for Xtables
 *      Patched by Egor Vorontsov <sdoregor@sdore.me>
 *      to support `iif', based on "TEE" target.
 *
 *	Copyright © Sebastian Claßen, 2007
 *	Jan Engelhardt, 2007-2010
 *
 *	based on ipt_ROUTE.c from Cédric de Launois
 *	<delaunois@info.ucl.be>
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#include <linux/netfilter/x_tables.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/netfilter/ipv4/nf_dup_ipv4.h>
#include <net/netfilter/ipv6/nf_dup_ipv6.h>
#include "xt_XTEE.h"

struct xt_xtee_priv {
	struct list_head	list;
	struct xt_xtee_tginfo	*tginfo;
	int			oif;
	int			iif;
};

static unsigned int xtee_net_id __read_mostly;
static const union nf_inet_addr xtee_zero_address;

struct xtee_net {
	struct list_head priv_list;
	/* lock protects the priv_list */
	struct mutex lock;
};

static unsigned int
xtee_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_xtee_tginfo *info = par->targinfo;
	int oif = info->priv ? info->priv->oif : 0;
	int iif = info->priv ? info->priv->iif : 0;

	if (memcmp(&info->gw, &xtee_zero_address, sizeof(xtee_zero_address)))
		nf_dup_ipv4(xt_net(par), skb, xt_hooknum(par), &info->gw.in, oif);

	if (iif == -1)
		return NF_DROP;
	else if (iif) {
		struct net_device *dev_in = NULL;

		if (!(dev_in = dev_get_by_index(xt_net(par), iif))) {
			if (net_ratelimit())
				pr_debug("ipt_XTEE: iif interface %d not found\n", iif);
			return NF_DROP;
		}

		skb->dev = dev_in;
		skb_dst_drop(skb);
		skb->protocol = htons(ETH_P_IP);

		netif_rx(skb);
		return NF_STOLEN;
	}

	return XT_CONTINUE;
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static unsigned int
xtee_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_xtee_tginfo *info = par->targinfo;
	int oif = info->priv ? info->priv->oif : 0;
	int iif = info->priv ? info->priv->iif : 0;

	if (memcmp(&info->gw, &xtee_zero_address, sizeof(xtee_zero_address)))
		nf_dup_ipv6(xt_net(par), skb, xt_hooknum(par), &info->gw.in6, oif);

	if (iif == -1)
		return NF_DROP;
	else if (iif) {
		struct net_device *dev_in = NULL;

		if (!(dev_in = dev_get_by_index(xt_net(par), iif))) {
			if (net_ratelimit())
				pr_debug("ipt_XTEE: iif interface %d not found\n", iif);
			return NF_DROP;
		}

		skb->dev = dev_in;
		skb_dst_drop(skb);
		skb->protocol = htons(ETH_P_IPV6);

		netif_rx(skb);
		return NF_STOLEN;
	}

	return XT_CONTINUE;
}
#endif

static int xtee_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(dev);
	struct xtee_net *tn = net_generic(net, xtee_net_id);
	struct xt_xtee_priv *priv;

	mutex_lock(&tn->lock);
	list_for_each_entry(priv, &tn->priv_list, list) {
		switch (event) {
		case NETDEV_REGISTER:
			if (!strcmp(dev->name, priv->tginfo->oif))
				priv->oif = dev->ifindex;

			if (!strcmp(dev->name, priv->tginfo->iif))
				priv->iif = dev->ifindex;

			break;
		case NETDEV_UNREGISTER:
			if (dev->ifindex == priv->oif)
				priv->oif = -1;

			if (dev->ifindex == priv->iif)
				priv->iif = -1;

			break;
		case NETDEV_CHANGENAME:
			if (!strcmp(dev->name, priv->tginfo->oif))
				priv->oif = dev->ifindex;
			else if (dev->ifindex == priv->oif)
				priv->oif = -1;

			if (!strcmp(dev->name, priv->tginfo->iif))
				priv->iif = dev->ifindex;
			else if (dev->ifindex == priv->iif)
				priv->iif = -1;

			break;
		}
	}
	mutex_unlock(&tn->lock);

	return NOTIFY_DONE;
}

static int xtee_tg_check(const struct xt_tgchk_param *par)
{
	struct xtee_net *tn = net_generic(par->net, xtee_net_id);
	struct xt_xtee_tginfo *info = par->targinfo;
	struct xt_xtee_priv *priv;

	/* 0.0.0.0 and :: not allowed */
	if (*info->iif == '\0' && memcmp(&info->gw, &xtee_zero_address, sizeof(xtee_zero_address)) == 0)
		return -EINVAL;

	if (*info->oif != '\0' || *info->iif != '\0') {
		struct net_device *dev;

		if (*info->oif != '\0' && info->oif[sizeof(info->oif)-1] != '\0')
			return -EINVAL;
		if (*info->iif != '\0' && info->iif[sizeof(info->iif)-1] != '\0')
			return -EINVAL;

		priv = kzalloc(sizeof(*priv), GFP_KERNEL);
		if (priv == NULL)
			return -ENOMEM;

		priv->tginfo  = info;
		priv->oif     = -1;
		priv->iif     = -1;
		info->priv    = priv;

		dev = dev_get_by_name(par->net, info->oif);
		if (dev) {
			priv->oif = dev->ifindex;
			dev_put(dev);
		}
		dev = dev_get_by_name(par->net, info->iif);
		if (dev) {
			priv->iif = dev->ifindex;
			dev_put(dev);
		}

		mutex_lock(&tn->lock);
		list_add(&priv->list, &tn->priv_list);
		mutex_unlock(&tn->lock);
	} else
		info->priv = NULL;

	return 0;
}

static void xtee_tg_destroy(const struct xt_tgdtor_param *par)
{
	struct xtee_net *tn = net_generic(par->net, xtee_net_id);
	struct xt_xtee_tginfo *info = par->targinfo;

	if (info->priv) {
		mutex_lock(&tn->lock);
		list_del(&info->priv->list);
		mutex_unlock(&tn->lock);
		kfree(info->priv);
	}
}

static struct xt_target xtee_tg_reg[] __read_mostly = {
	{
		.name       = "XTEE",
		.revision   = 1,
		.family     = NFPROTO_IPV4,
		.target     = xtee_tg4,
		.targetsize = sizeof(struct xt_xtee_tginfo),
		.usersize   = offsetof(struct xt_xtee_tginfo, priv),
		.checkentry = xtee_tg_check,
		.destroy    = xtee_tg_destroy,
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name       = "XTEE",
		.revision   = 1,
		.family     = NFPROTO_IPV6,
		.target     = xtee_tg6,
		.targetsize = sizeof(struct xt_xtee_tginfo),
		.usersize   = offsetof(struct xt_xtee_tginfo, priv),
		.checkentry = xtee_tg_check,
		.destroy    = xtee_tg_destroy,
		.me         = THIS_MODULE,
	},
#endif
};

static int __net_init xtee_net_init(struct net *net)
{
	struct xtee_net *tn = net_generic(net, xtee_net_id);

	INIT_LIST_HEAD(&tn->priv_list);
	mutex_init(&tn->lock);
	return 0;
}

static struct pernet_operations xtee_net_ops = {
	.init = xtee_net_init,
	.id   = &xtee_net_id,
	.size = sizeof(struct xtee_net),
};

static struct notifier_block xtee_netdev_notifier = {
	.notifier_call = xtee_netdev_event,
};

static int __init xtee_tg_init(void)
{
	int ret;

	ret = register_pernet_subsys(&xtee_net_ops);
	if (ret < 0)
		return ret;

	ret = xt_register_targets(xtee_tg_reg, ARRAY_SIZE(xtee_tg_reg));
	if (ret < 0)
		goto cleanup_subsys;

	ret = register_netdevice_notifier(&xtee_netdev_notifier);
	if (ret < 0)
		goto unregister_targets;

	return 0;

unregister_targets:
	xt_unregister_targets(xtee_tg_reg, ARRAY_SIZE(xtee_tg_reg));
cleanup_subsys:
	unregister_pernet_subsys(&xtee_net_ops);
	return ret;
}

static void __exit xtee_tg_exit(void)
{
	unregister_netdevice_notifier(&xtee_netdev_notifier);
	xt_unregister_targets(xtee_tg_reg, ARRAY_SIZE(xtee_tg_reg));
	unregister_pernet_subsys(&xtee_net_ops);
}

module_init(xtee_tg_init);
module_exit(xtee_tg_exit);
MODULE_AUTHOR("Sebastian Claßen <sebastian.classen@freenet.ag>");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_AUTHOR("Egor Vorontsov <sdoregor@sdore.me>");
MODULE_DESCRIPTION("Xtables: Reroute packet copy (with `iif' patch)");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_XTEE");
MODULE_ALIAS("ip6t_XTEE");
