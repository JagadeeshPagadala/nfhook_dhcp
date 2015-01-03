#include <linux/in.h>

/* verify this strutcure with RFC sname and file may be wrong*/
/* Reference: taken from dhcp user space tool <include/dhcp.h>*/


#define DHCP_UDP_OVERHEAD	(20 + /* IP header */			\
			        8)   /* UDP header */
#define DHCP_SNAME_LEN		64
#define DHCP_FILE_LEN		128
#define DHCP_FIXED_NON_UDP	236
#define DHCP_FIXED_LEN		(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
						/* Everything but options. */
#define BOOTP_MIN_LEN		300

#define DHCP_MTU_MAX		1500
#define DHCP_MTU_MIN            576

#define DHCP_MAX_OPTION_LEN	(DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN     (DHCP_MTU_MIN - DHCP_FIXED_LEN)

struct dhcp_packet {
 u_int8_t  op;		/* 0: Message opcode/type */
	u_int8_t  htype;	/* 1: Hardware addr type (net/if_types.h) */
	u_int8_t  hlen;		/* 2: Hardware addr length */
	u_int8_t  hops;		/* 3: Number of relay agent hops from client */
	u_int32_t xid;		/* 4: Transaction ID */
	u_int16_t secs;		/* 8: Seconds since client started looking */
	u_int16_t flags;	/* 10: Flag bits */
	struct in_addr ciaddr;	/* 12: Client IP address (if already in use) */
	struct in_addr yiaddr;	/* 16: Client IP address */
	struct in_addr siaddr;	/* 18: IP address of next server to talk to */
	struct in_addr giaddr;	/* 20: DHCP relay agent IP address */
	unsigned char chaddr [16];	/* 24: Client hardware address */
	char sname [DHCP_SNAME_LEN];	/* 40: Server name */
	char file [DHCP_FILE_LEN];	/* 104: Boot filename */
	unsigned char options [DHCP_MAX_OPTION_LEN];
				/* 212: Optional parameters
			  (actual length dependent on MTU). */
};

/* BOOTP (rfc951) message types */
#define	BOOTREQUEST	1
#define BOOTREPLY	2

