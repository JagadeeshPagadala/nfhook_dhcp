#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jagadeesh");

/**	
* 	Global variables	
**/

/*
*	Netfilter Hook function
*/
unsigned int hook_func (unsigned int hooknum, struct sk_buff *skb, 
		const struct net_device *in,
		const struct net_device *out, int (*okfn) (struct sk_buff *))
{
	printk("packet received");
	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
	.hook	= hook_func,
	.owner	= THIS_MODULE,
	.pf	= PF_INET, /* PF_BRIDGE is for bridge interface and PF_INET for IPv4 */
	.hooknum = NF_INET_FORWARD, /* Refer netfiletr packet path diagram */
	.priority = NF_IP_PRI_FIRST,
};

static int nfhook_init(void)
{
	int ret = 0;
	ret = nf_register_hook(&nfho); /* It return 0 always */
	
	return 0;	
}

static void nfhook_exit(void)
{
	nf_unregister_hook(&nfho);	
}

module_init(nfhook_init);
module_exit(nfhook_exit);
