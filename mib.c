/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 1990  Mentat Inc.
 * netstat.c 2.2, last change 9/9/91
 * MROUTING Revision 3.5
 */
/*
 * ripped from netstat.c by Dave Eddy <dave@daveeddy.com> 2015
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <unistd.h>

#include <inet/mib2.h>

#include <netinet/in.h>
#include <netinet/ip_mroute.h>

#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/tihdr.h>
#include <sys/types.h>

#include "mib.h"

/**
 * mibopen
 *
 * pass in opts like mibopen({"arp", "tcp", "udp", NULL})
 */
int mibopen(char **opts) {
	int sd = sd = open("/dev/arp", O_RDWR);
	if (sd == -1)
		return -1;

	char *opt;
	while ((opt = *opts++)) {
		if (ioctl(sd, I_PUSH, opt) == -1) {
			close(sd);
			return -1;
		}
	}

	return sd;
}

mib_item_t *mibget(int sd) {
	/*
	 * buf is an automatic for this function, so the
	 * compiler has complete control over its alignment;
	 * it is assumed this alignment is satisfactory for
	 * it to be casted to certain other struct pointers
	 * here, such as struct T_optmgmt_ack * .
	 */
	uintptr_t		buf[512 / sizeof (uintptr_t)];
	int			flags;
	int			j, getcode;
	struct strbuf		ctlbuf, databuf;
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req;
	mib_item_t		*first_item = NULL;
	mib_item_t		*last_item  = NULL;
	mib_item_t		*temp;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;


	/*
	 * Note: we use the special level value below so that IP will return
	 * us information concerning IRE_MARK_TESTHIDDEN routes.
	 */
	req = (struct opthdr *)&tor[1];
	req->level = EXPER_IP_AND_ALL_IRES;
	req->name  = 0;
	req->len   = 1;

	ctlbuf.buf = (char *)buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, (struct strbuf *)0, flags) == -1) {
		perror("mibget: putmsg(ctl) failed");
		goto error_exit;
	}

	/*
	 * Each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	j = 1;
	for (;;) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, (struct strbuf *)0, &flags);
		if (getcode == -1) {
			perror("mibget getmsg(ctl) failed");
			goto error_exit;
		}
		if (getcode == 0 &&
		    ctlbuf.len >= sizeof (struct T_optmgmt_ack) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    req->len == 0) {
			return (first_item);		/* this is EOD msg */
		}

		if (ctlbuf.len >= sizeof (struct T_error_ack) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			(void) fprintf(stderr,
			    "mibget %d gives T_ERROR_ACK: TLI_error = 0x%lx, "
			    "UNIX_error = 0x%lx\n",
			    j, tea->TLI_error, tea->UNIX_error);

			errno = (tea->TLI_error == TSYSERR) ?
			    tea->UNIX_error : EPROTO;
			goto error_exit;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			(void) printf("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %ld\n",
			    j, getcode, ctlbuf.len, toa->PRIM_type);

			if (toa->PRIM_type == T_OPTMGMT_ACK)
				(void) printf("T_OPTMGMT_ACK: "
				    "MGMT_flags = 0x%lx, req->len = %ld\n",
				    toa->MGMT_flags, req->len);
			errno = ENOMSG;
			goto error_exit;
		}

		temp = (mib_item_t *)malloc(sizeof (mib_item_t));
		if (temp == NULL) {
			perror("mibget malloc failed");
			goto error_exit;
		}
		if (last_item != NULL)
			last_item->next_item = temp;
		else
			first_item = temp;
		last_item = temp;
		last_item->next_item = NULL;
		last_item->group = req->level;
		last_item->mib_id = req->name;
		last_item->length = req->len;
		last_item->valp = malloc((int)req->len);
		if (last_item->valp == NULL)
			goto error_exit;

		databuf.maxlen = last_item->length;
		databuf.buf    = (char *)last_item->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, (struct strbuf *)0, &databuf, &flags);
		if (getcode == -1) {
			perror("mibget getmsg(data) failed");
			goto error_exit;
		} else if (getcode != 0) {
			(void) printf("mibget getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d\n",
			    getcode, databuf.maxlen, databuf.len);
			goto error_exit;
		}
		j++;
	}
	/* NOTREACHED */

error_exit:;
	mibfree(first_item);
	return (NULL);
}

/*
 * mibfree: frees a linked list of type (mib_item_t *)
 * returned by mibget(); this is NOT THE SAME AS
 * mib_item_destroy(), so should be used for objects
 * returned by mibget() only
 */
void mibfree(mib_item_t *firstitem) {
	mib_item_t *lastitem;

	while (firstitem != NULL) {
		lastitem = firstitem;
		firstitem = firstitem->next_item;
		if (lastitem->valp != NULL)
			free(lastitem->valp);
		free(lastitem);
	}
}

/* Extract constant sizes */
void mib_get_constants(mib_item_t *item) {
	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (item->mib_id != 0)
			continue; /* 'for' loop 1 */

		switch (item->group) {
		case MIB2_IP: {
			mib2_ip_t	*ip = (mib2_ip_t *)item->valp;

			ipAddrEntrySize = ip->ipAddrEntrySize;
			ipRouteEntrySize = ip->ipRouteEntrySize;
			ipNetToMediaEntrySize = ip->ipNetToMediaEntrySize;
			ipMemberEntrySize = ip->ipMemberEntrySize;
			ipGroupSourceEntrySize = ip->ipGroupSourceEntrySize;
			ipRouteAttributeSize = ip->ipRouteAttributeSize;
			transportMLPSize = ip->transportMLPSize;
			ipDestEntrySize = ip->ipDestEntrySize;
			assert(IS_P2ALIGNED(ipAddrEntrySize,
			    sizeof (mib2_ipAddrEntry_t *)));
			assert(IS_P2ALIGNED(ipRouteEntrySize,
			    sizeof (mib2_ipRouteEntry_t *)));
			assert(IS_P2ALIGNED(ipNetToMediaEntrySize,
			    sizeof (mib2_ipNetToMediaEntry_t *)));
			assert(IS_P2ALIGNED(ipMemberEntrySize,
			    sizeof (ip_member_t *)));
			assert(IS_P2ALIGNED(ipGroupSourceEntrySize,
			    sizeof (ip_grpsrc_t *)));
			assert(IS_P2ALIGNED(ipRouteAttributeSize,
			    sizeof (mib2_ipAttributeEntry_t *)));
			assert(IS_P2ALIGNED(transportMLPSize,
			    sizeof (mib2_transportMLPEntry_t *)));
			break;
		}
		case EXPER_DVMRP: {
			struct mrtstat	*mrts = (struct mrtstat *)item->valp;

			vifctlSize = mrts->mrts_vifctlSize;
			mfcctlSize = mrts->mrts_mfcctlSize;
			assert(IS_P2ALIGNED(vifctlSize,
			    sizeof (struct vifclt *)));
			assert(IS_P2ALIGNED(mfcctlSize,
			    sizeof (struct mfcctl *)));
			break;
		}
		case MIB2_IP6: {
			mib2_ipv6IfStatsEntry_t *ip6;
			/* Just use the first entry */

			ip6 = (mib2_ipv6IfStatsEntry_t *)item->valp;
			ipv6IfStatsEntrySize = ip6->ipv6IfStatsEntrySize;
			ipv6AddrEntrySize = ip6->ipv6AddrEntrySize;
			ipv6RouteEntrySize = ip6->ipv6RouteEntrySize;
			ipv6NetToMediaEntrySize = ip6->ipv6NetToMediaEntrySize;
			ipv6MemberEntrySize = ip6->ipv6MemberEntrySize;
			ipv6GroupSourceEntrySize =
			    ip6->ipv6GroupSourceEntrySize;
			assert(IS_P2ALIGNED(ipv6IfStatsEntrySize,
			    sizeof (mib2_ipv6IfStatsEntry_t *)));
			assert(IS_P2ALIGNED(ipv6AddrEntrySize,
			    sizeof (mib2_ipv6AddrEntry_t *)));
			assert(IS_P2ALIGNED(ipv6RouteEntrySize,
			    sizeof (mib2_ipv6RouteEntry_t *)));
			assert(IS_P2ALIGNED(ipv6NetToMediaEntrySize,
			    sizeof (mib2_ipv6NetToMediaEntry_t *)));
			assert(IS_P2ALIGNED(ipv6MemberEntrySize,
			    sizeof (ipv6_member_t *)));
			assert(IS_P2ALIGNED(ipv6GroupSourceEntrySize,
			    sizeof (ipv6_grpsrc_t *)));
			break;
		}
		case MIB2_ICMP6: {
			mib2_ipv6IfIcmpEntry_t *icmp6;
			/* Just use the first entry */

			icmp6 = (mib2_ipv6IfIcmpEntry_t *)item->valp;
			ipv6IfIcmpEntrySize = icmp6->ipv6IfIcmpEntrySize;
			assert(IS_P2ALIGNED(ipv6IfIcmpEntrySize,
			    sizeof (mib2_ipv6IfIcmpEntry_t *)));
			break;
		}
		case MIB2_TCP: {
			mib2_tcp_t	*tcp = (mib2_tcp_t *)item->valp;

			tcpConnEntrySize = tcp->tcpConnTableSize;
			tcp6ConnEntrySize = tcp->tcp6ConnTableSize;
			assert(IS_P2ALIGNED(tcpConnEntrySize,
			    sizeof (mib2_tcpConnEntry_t *)));
			assert(IS_P2ALIGNED(tcp6ConnEntrySize,
			    sizeof (mib2_tcp6ConnEntry_t *)));
			break;
		}
		case MIB2_UDP: {
			mib2_udp_t	*udp = (mib2_udp_t *)item->valp;

			udpEntrySize = udp->udpEntrySize;
			udp6EntrySize = udp->udp6EntrySize;
			assert(IS_P2ALIGNED(udpEntrySize, sizeof (mib2_udpEntry_t *)));
			assert(IS_P2ALIGNED(udp6EntrySize, sizeof (mib2_udp6Entry_t *)));
			break;
		}
		case MIB2_SCTP: {
			mib2_sctp_t	*sctp = (mib2_sctp_t *)item->valp;

			sctpEntrySize = sctp->sctpEntrySize;
			sctpLocalEntrySize = sctp->sctpLocalEntrySize;
			sctpRemoteEntrySize = sctp->sctpRemoteEntrySize;
			break;
		}
		}
	}
}
