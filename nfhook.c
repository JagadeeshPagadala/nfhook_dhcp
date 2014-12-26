#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jagadeesh");


/**	
* 	Global variables	
**/

/* */
static int is_udp(struct sk_buff *skb)
{
	/* */
	struct iphdr *ip_header;

	ip_header = ip_hdr(skb);
	/* IP protocol Number of UDP is IPPROTO_UDP(17). See linux/in.h*/
	if (ip_header->protocol == IPPROTO_UDP ) {
		return 0;
	}
	return 1;
}

/* */
static int is_dhcp(struct sk_buff *skb)
{	
	struct udphdr *udp_header;

	udp_header = (struct udphdr *)udp_hdr(skb);
	if(udp_header->source == htonl(DHCP_SERVER_PORT) || \
		udp_header->dest == htons(DHCP_SERVER_PORT) || \
		(udp_header->source == htons(DHCP_CLIENT_PORT)) || \
		(udp_header->dest == htons(DHCP_CLIENT_PORT))) {
			return 1;

		}
	return 0;
}
/* */
static int is_dhcp_ack(struct sk_buff *skb)
{
	/* Add logic to check is packet dhcp_ack */
	return 0;
}

/*
*	Netfilter Hook function
*/
unsigned int hook_func (unsigned int hooknum, struct sk_buff *skb, 
		const struct net_device *in,
		const struct net_device *out, int (*okfn) (struct sk_buff *))
{
	int ret = 0;

	pr_debug("%s:packet received \n",__FUNCTION__);
#ifdef PRINTK_DEBUG	
	printk("%s:packet received \n",__FUNCTION__);
#endif
	/* Check only Internet Protocol(IP) packets*/
	/* Check if_ether.h */
	if (skb->protocol != htons (ETH_P_IP)) {
		//pr_debug("%s:hook_fun \n",__FUNCTION__);
		return NF_ACCEPT;
	}
	/* Check for UPD packet */
	ret = is_udp(skb);
	if (ret != 0) {
		pr_debug("%s:hook_func: UDP packet RXd \n",__FUNCTION__);
		return NF_ACCEPT;
	}
	pr_debug("%s: UDP packet RXd \n",__FUNCTION__);
#ifdef PRINTK_DEBUG	
	printk("%s: UDP packet RXd \n",__FUNCTION__);
#endif
	/* Check for DHCP packet */
	ret = is_dhcp(skb);
	if (ret != 0) {
		return NF_ACCEPT;
	}
	pr_debug("%s:DHCP packet RXd \n",__FUNCTION__);
#ifdef PRINTK_DEBUG	
	printk("%s: DHCP packet RXd \n",__FUNCTION__);
#endif 
	/* If packet RX is DHCP packet */
	/* Check for DHCP ACK */
	ret = is_dhcp_ack(skb);
	if (ret != 0 ) {
		return NF_ACCEPT;
	}
	pr_debug("%s:DHCP ACK packet RXd \n",__FUNCTION__);
#ifdef PRINTK_DEBUG	
	printk("%s: DHCP ACK packet RXd \n",__FUNCTION__);
#endif 
	/* If we reach here, dhcp_ack packet */
	return NF_ACCEPT;
}


static struct nf_hook_ops nfho = { 
	.hook	= hook_func,
	.owner	= THIS_MODULE,
	.pf	= PF_INET, /* PF_BRIDGE is for bridge interface and PF_INET for IPv4 */
	.hooknum = NF_INET_LOCAL_IN,//NF_INET_FORWARD, /* Refer netfiletr packet path diagram */
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
