/* dhcpd.h */
#ifndef _DHCPC_H
#define _DHCPC_H


#define INIT_SELECTING	0
#define REQUESTING	1
#define BOUND		2
#define RENEWING	3
#define REBINDING	4
#define INIT_REBOOT	5
#define RENEW_REQUESTED 6
#define RELEASED	7
#ifdef GPL_A_SUPPORT_6RD
#define DHCP_6RD	212
#endif
#if defined(GPL_CODE_A)
#define MAC_INVALID_ADDR    "\x00\x00\x00\x00\x00\x00"
#endif

/* Paramaters the client should request from the server */

#ifdef GPL_A_SUPPORT_6RD
#define PARM_REQUESTS \
	DHCP_SUBNET, \
	DHCP_ROUTER, \
	DHCP_DNS_SERVER, \
	DHCP_HOST_NAME, \
	DHCP_DOMAIN_NAME, \
	DHCP_BROADCAST, \
	DHCP_6RD

#else
#define PARM_REQUESTS \
	DHCP_SUBNET, \
	DHCP_ROUTER, \
	DHCP_DNS_SERVER, \
	DHCP_HOST_NAME, \
	DHCP_DOMAIN_NAME, \
	DHCP_BROADCAST
#endif

struct client_config_t {
	char foreground;		/* Do not fork */
	char quit_after_lease;		/* Quit after obtaining lease */
	char abort_if_no_lease;		/* Abort if no lease */
	char *interface;		/* The name of the interface to use */
	char *pidfile;			/* Optionally store the process ID */
	char *script;			/* User script to run at dhcp events */
	char *clientid;			/* Optional client id to use */
	char *hostname;			/* Optional hostname to use */
	int ifindex;			/* Index number of the interface to use */
	unsigned char arp[6];		/* Our arp address */
};

extern struct client_config_t client_config;

#ifdef GPL_CODE
#define OPTION55_MAX_LEN 20
extern char list[OPTION55_MAX_LEN];
struct aei_wan_info_t {
    char ip[32];
    char mask[32];
    char gateway[32];
    char nameserver[64];
};
#endif

// brcm
extern int ipv6rd_opt;
extern char vendor_class_id[];
extern char en_vendor_class_id;
extern char en_client_id;
extern char duid[];
extern char iaid[];
extern char user_class_id[];
extern char en_user_class_id;
extern char en_125;
extern char oui_125[];
extern char sn_125[];
extern char prod_125[];
#ifdef GPL_CODE_TT
extern char mn_125[];
#endif
#endif
