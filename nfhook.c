#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jagadeesh");


/*
 *	Global variables
 */

/* return '1' if packet is TCP */
static int is_tcp(struct sk_buff *skb)
{

	struct iphdr *ip_header;

	ip_header = ip_hdr(skb);
	/* IP protocol Number of UDP is IPPROTO_UDP(17). See linux/in.h*/
	/* TODO: Check does evry packet contians IP hdr*/
	if (ip_header->protocol == IPPROTO_TCP)
		return 1;

	return 0;
}

/*
 *
 */
static int is_http(struct sk_buff *skb)
{

	struct tcphdr *tcp_header;

	tcp_header = tcp_hdr(skb);
	if (tcp_header->source == htons(DHCP_SERVER_PORT) ||
		tcp_header->dest == htons(DHCP_SERVER_PORT) ||
		(tcp_header->source == htons(DHCP_CLIENT_PORT)) ||
		(tcp_header->dest == htons(DHCP_CLIENT_PORT))) {
			return 1;
		}

	return 0;
}

/*
 *	Netfilter Hook function
 */
static unsigned int hook_func (void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{

	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
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
	/* Check for TCP packet */
	ret = is_tcp(skb);
	if (ret != 1) {
		pr_debug("%s:hook_func: TCP packet RXd\n", __func__);
		return NF_ACCEPT;
	}
	pr_debug("%s: TCP packet RXd\n", __func__);
#ifdef PRINTK_DEBUG
	printk(KERN_DEBUG"%s: TCP packet RXd\n", __func__);
#endif
	tcp_header = tcp_hdr(skb);
	ip_header = ip_hdr(skb);
	/*if (ntohs(tcp_header->dest) >=10000 || ntohs(tcp_header->dest) < 9999) {
		tcp_header->dest = htons(1000);
		ip_header->daddr = htonl(3232267287);
	}*/
	/*Redirect SSH packet to port number 2200 on 192.168.241.129*/
	if (ntohs(tcp_header->dest) == 22) {
		tcp_header->dest = htons(2200);
		ip_header->daddr = htonl(3232297345);
		printk("changing the port 22 to 2200");
		return NF_ACCEPT;
	}
	/* Check for HTTP packet */
	ret = is_http(skb);
	if (ret != 1) {
		pr_debug("%s:hook_func: TCP packet RXd\n", __func__);
		return NF_ACCEPT;
	}
	pr_debug("%s:HTTP packet RXd\n", __func__);
#ifdef PRINTK_DEBUG
	printk(KERN_DEBUG"%s: HTTP packet RXd\n", __func__);
#endif
	/*If port is in 
	 * range:1000-19999 -> redirect to servr1:8000
	 * range:2000-29999 -> redirect to server:9000*/
	/*
	 * Change the dest IP and dest port respectively 
	 */

	return NF_ACCEPT;
}

/* Hook for Incoming packets (PRE ROUTING) */
static struct nf_hook_ops pre_nfho = {
	.hook	= hook_func,
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

static int nfhook_init(void)
{
	int ret = 0;

	ret = nf_register_net_hook(&init_net, &pre_nfho); /* It return 0 always */

	return 0;
}

static void nfhook_exit(void)
{
	nf_unregister_net_hook(&init_net, &pre_nfho);
}

module_init(nfhook_init);
module_exit(nfhook_exit);
