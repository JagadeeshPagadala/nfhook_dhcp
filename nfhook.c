#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "dhcp_packet.h"
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jagadeesh");


/*
 *	Global variables
 */

/* return '1' if packet is dhcp */
static int is_udp(struct sk_buff *skb)
{

	struct iphdr *ip_header;

	ip_header = ip_hdr(skb);
	/* IP protocol Number of UDP is IPPROTO_UDP(17). See linux/in.h*/
	/* TODO: Check does evry packet contians IP hdr*/
	if (ip_header->protocol == IPPROTO_UDP)
		return 1;

	return 0;
}

/*
 *
 */
static int is_dhcp(struct sk_buff *skb)
{

	struct udphdr *udp_header;

	udp_header = (struct udphdr *)udp_hdr(skb);
	if (udp_header->source == htons(DHCP_SERVER_PORT) ||
		udp_header->dest == htons(DHCP_SERVER_PORT) ||
		(udp_header->source == htons(DHCP_CLIENT_PORT)) ||
		(udp_header->dest == htons(DHCP_CLIENT_PORT))) {
			return 1;
		}

	return 0;
}
/*
 *
 */
static void dhcp_pkt_type(struct sk_buff *skb)
{

	struct udphdr *udp_header;
	unsigned char *udp_data;
	unsigned int type = 0, type_offset = 0;
	/*u_int8_t op, htype;*/

	udp_header = udp_hdr(skb);
	/* get start of udp data*/
	udp_data = ((char *)udp_header + sizeof(struct udphdr));
	/*type = *((int*)(udp_data + sizeof(struct udphdr)));*/
	type_offset = 1+1+1+1+4+2+2+4+4+4+4+16+64+128+4+2;
	type = *(udp_data + type_offset);  /* type is 1 byte data */
	printk(KERN_DEBUG"\n%s: dhcp-packet type %d\n", __func__, type);

	return ;
}

/*
 *	Netfilter Hook function
 */
static unsigned int hook_func (const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn) (struct sk_buff *))
{
	int ret = 0;

	pr_debug("%s:packet received\n", __func__);
#ifdef PRINTK_DEBUG
	printk(KERN_DEBUG"%s:packet received\n", __func__);
#endif
	/* Check only Internet Protocol(IP) packets*/
	/* Check if_ether.h */
	if (skb->protocol != htons(ETH_P_IP)) {
		/*pr_debug("%s:hook_fun\n", __func__);*/
		return NF_ACCEPT;
	}
	/* Check for UPD packet */
	ret = is_udp(skb);
	if (ret != 1) {
		pr_debug("%s:hook_func: UDP packet RXd\n", __func__);
		return NF_ACCEPT;
	}
	pr_debug("%s: UDP packet RXd\n", __func__);
#ifdef PRINTK_DEBUG
	printk(KERN_DEBUG"%s: UDP packet RXd\n", __func__);
#endif
	/* Check for DHCP packet */
	ret = is_dhcp(skb);
	if (ret != 1)
		return NF_ACCEPT;

	pr_debug("%s:DHCP packet RXd\n", __func__);
#ifdef PRINTK_DEBUG
	printk(KERN_DEBUG"%s: DHCP packet RXd\n", __func__);
#endif
	/* If packet RX is DHCP packet */
	/* Check for DHCP PKT Type */
	dhcp_pkt_type(skb);

	return NF_ACCEPT;
}

/* Hook for Incoming packets (PRE ROUTING) */
static struct nf_hook_ops pre_nfho = {
	.hook	= hook_func,
	.owner	= THIS_MODULE,
	.pf	= PF_INET, /* PF_BRIDGE is for bridge interface and  \
							PF_INET for IPv4 */
	/*TODO:
	*1. If hook is registered at PRE_ROUTING then able to see DHCP Pkts
	*2. If hook is registered at LOCAL_IN not able to see DHCP Packet.
	*Reason:
	* May be LOCAL_IN hook is processed only if packet is having IP addr
	*	same as Interface IP.
	*	If server is broadcasting DHCP ACK then,
	*	LOCAL_IN will not get the packet
	*/
	.hooknum = NF_INET_PRE_ROUTING,
	/*.hooknum = NF_INET_LOCAL_IN, change to NF_INET_FORWARD to \
		capture on arouter,  Refer netfiletr packet path diagram */
	.priority = NF_IP_PRI_FIRST,
	/* Priority of the function within the hook (i.e. hooknum),
			hook fn will be invoked in the priority order*/
};

/* Hook for Outgoing packets (POST ROUTING)*/
static struct nf_hook_ops post_nfho = {
	.hook		= hook_func,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
};

static int nfhook_init(void)
{
	int ret = 0;

	ret = nf_register_hook(&pre_nfho); /* It return 0 always */
	ret = nf_register_hook(&post_nfho); /* It return 0 always */

	return 0;
}

static void nfhook_exit(void)
{
	nf_unregister_hook(&pre_nfho);
	nf_unregister_hook(&post_nfho);
}

module_init(nfhook_init);
module_exit(nfhook_exit);
