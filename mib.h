/**
 * mib* functions used to interface with /dev/arp
 *
 * These functions have been ripped from netstat.c
 * (usr/src/cmd/cmd-inet/usr.bin/netstat/netstat.c)
 * and some modified slightly
 *
 * License: CDDL
 */

#include <sys/types.h>

/*
 * Sizes of data structures extracted from the base mib.
 * This allows the size of the tables entries to grow while preserving
 * binary compatibility.
 */
int ipAddrEntrySize;
int ipRouteEntrySize;
int ipNetToMediaEntrySize;
int ipMemberEntrySize;
int ipGroupSourceEntrySize;
int ipRouteAttributeSize;
int vifctlSize;
int mfcctlSize;

int ipv6IfStatsEntrySize;
int ipv6IfIcmpEntrySize;
int ipv6AddrEntrySize;
int ipv6RouteEntrySize;
int ipv6NetToMediaEntrySize;
int ipv6MemberEntrySize;
int ipv6GroupSourceEntrySize;

int ipDestEntrySize;

int transportMLPSize;
int tcpConnEntrySize;
int tcp6ConnEntrySize;
int udpEntrySize;
int udp6EntrySize;
int sctpEntrySize;
int sctpLocalEntrySize;
int sctpRemoteEntrySize;

typedef struct mib_item_s {
	struct mib_item_s	*next_item;
	int			group;
	int			mib_id;
	int			length;
	void			*valp;
} mib_item_t;

int mibopen(char **opts);
mib_item_t *mibget(int sd);
void mibfree(mib_item_t *firstitem);
void mib_get_constants(mib_item_t *item);
