/**
 * get open socket information on the current host
 *
 * output inspired by sockstat(1) on FreeBSD
 *
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: March 22, 2015
 * License: CDDL
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zone.h>

#include <procfs.h>
#include <libzonecfg.h>

#include <arpa/inet.h>

#include <inet/mib2.h>
#include <inet/tcp.h>

#include <netinet/in.h>
#include <netinet/ip_mroute.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "mib.h"
#include "proc_info.h"

#define IN_IS_ADDR_LOOPBACK(addr) ((ntohl(addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)

static void print_line(int af, char *proto, int pid, void *lip, uint_t lport, void *rip, uint_t rport);
static void report(const mib_item_t *item);

#define FMT_ZONES  "%-15s "

#define FMT_HEADER "%-9s %-15s %-6s %-6s %-22s %-22s %s\n"
#define FMT_BODY   "%-9s %-15s %-6d %-6s %-22s %-22s %s\n"

struct {
	unsigned int v4 : 1;          // -4
	unsigned int v6 : 1;          // -6
	unsigned int args : 1;        // -a
	unsigned int connected : 1;   // -c
	unsigned int header : 1;      // -H
	unsigned int listening : 1;   // -l
	unsigned int p_tcp : 1;       // -P contains "tcp"
	unsigned int p_udp : 1;       // -P contains "udp"
	unsigned int loopback : 1;    // -L
	unsigned int zones : 1;       // -Z

	zoneid_t zone;                // -z
	char zroot[PATH_MAX];
} opts;

// print the usage message
static void usage(FILE *stream) {
	fprintf(stream, "usage: sockstat [-46acHhLlz] [-P protcols] [-z zone]\n");
	fprintf(stream, "\n");
	fprintf(stream, "print sockets in use on the current system\n");
	fprintf(stream, "\n");
	fprintf(stream, "options\n");
	fprintf(stream, "  -4             only show ipv4 sockets\n");
	fprintf(stream, "  -6             only show ipv6 sockets\n");
	fprintf(stream, "  -a             print process arguments\n");
	fprintf(stream, "  -c             only show connected sockets\n");
	fprintf(stream, "  -h             print this message and exit\n");
	fprintf(stream, "  -H             don't print header\n");
	fprintf(stream, "  -l             only show listening sockets\n");
	fprintf(stream, "  -L             hide sockets that pertain to the loopback address (127.0.0.0/8 or ::1)\n");
	fprintf(stream, "  -P <protos>    comma separated list of protocols, defaults to tcp,udp\n");
	fprintf(stream, "  -z <zone>      only show sockets inside zone\n");
	fprintf(stream, "  -Z             prefix lines with zone names\n");
	fprintf(stream, "\n");
	fprintf(stream, "- if neither '-4' or '-6' are supplied, both are assumed\n");
	fprintf(stream, "- if neither '-c' or '-l' are supplied, both are assumed\n");
	fprintf(stream, "\n");
}

// parse comma separated list of protocols and set opts accordingly
static void parse_protocols(char *protocols) {
	char *temp = protocols;
	char *protocol;
	while ((protocol = strsep(&temp, ","))) {
		if (strlen(protocol) == 0)
			continue;
		if (strcmp(protocol, "tcp") == 0)
			opts.p_tcp = 1;
		else if (strcmp(protocol, "udp") == 0)
			opts.p_udp = 1;
		else
			fprintf(stderr, "unknown protocol: %s\n", protocol);
	}
}

int main(int argc, char **argv) {
	char dev_arp[PATH_MAX];

	// defaults
	opts.header = 1;
	opts.loopback = 1;
	opts.zone = -1;

	// read options
	int c;
	while ((c = getopt(argc, argv, "46acHhLlP:Zz:")) != -1) {
		switch (c) {
			case '4':
				opts.v4 = 1;
				break;
			case '6':
				opts.v6 = 1;
				break;
			case 'a':
				opts.args = 1;
				break;
			case 'c':
				opts.connected = 1;
				break;
			case 'H':
				opts.header = 0;
				break;
			case 'h':
				usage(stdout);
				return 0;
			case 'L':
				opts.loopback = 0;
				break;
			case 'l':
				opts.listening = 1;
				break;
			case 'P':
				parse_protocols(optarg);
				break;
			case 'z':
				opts.zone = getzoneidbyname(optarg);
				if (opts.zone < 0) {
					fprintf(stderr, "failed to find zone %s: %s\n",
					    optarg, strerror(errno));
					return 1;
				}
				if (zone_get_rootpath(optarg, opts.zroot, sizeof (opts.zroot)) != Z_OK) {
					fprintf(stderr, "failed to get root path for %s\n", optarg);
					return 1;
				}
				break;
			case 'Z':
				opts.zones = 1;
				break;
			case '?':
			default:
				usage(stderr);
				return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (!opts.v4 && !opts.v6)
		opts.v4 = opts.v6 = 1;
	if (!opts.listening && !opts.connected)
		opts.connected = opts.listening = 1;
	if (!opts.p_tcp && !opts.p_udp)
		opts.p_tcp = opts.p_udp = 1;

	if (opts.header) {
		if (opts.zones)
			printf(FMT_ZONES, "ZONE");
		printf(FMT_HEADER,
		    "USER", "COMMAND", "PID", "PROTO",
		    "LOCAL ADDRESS", "REMOTE ADDRESS",
		    opts.args ? "ARGS" : "");
	}

	// construct /dev/arp file name
	dev_arp[0] = '\0';
	int index = 0;
	if (opts.zone >= 0) {
		strncat(dev_arp, opts.zroot, sizeof (dev_arp));
		index += strlen(opts.zroot);
	}
	strncat(dev_arp, "/dev/arp", sizeof (dev_arp) - index);
	// open /dev/arp
	printf("dev_arp = '%s'\n", dev_arp);
	char *mib_opts[] = {"tcp", "udp", NULL};
	int sd = mibopen(dev_arp, mib_opts);
	if (sd == -1) {
		perror("mibopen");
		return 1;
	}

	// read everything we need
	mib_item_t *item = mibget(sd);
	if (!item) {
		close(sd);
		perror("mibget");
		return 1;
	}
	close(sd);

	// load up constant values
	mib_get_constants(item);

	// show what we've found
	report(item);

	return 0;
}

static void tcp_report_item_v4(const mib2_tcpConnEntry_t *tp);
static void tcp_report_item_v6(const mib2_tcp6ConnEntry_t *tp6);
static void udp_report_item_v4(const mib2_udpEntry_t *ude);
static void udp_report_item_v6(const mib2_udp6Entry_t *ude6);

static void report(const mib_item_t *item) {
	mib2_udpEntry_t *ude;
	mib2_udp6Entry_t *ude6;
	mib2_tcpConnEntry_t *tp;
	mib2_tcp6ConnEntry_t *tp6;

	for (; item; item = item->next_item) {
		// filter for connections we care about
		switch (item->mib_id) {
			case MIB2_TCP_CONN:
			case MIB2_TCP6_CONN:
			case MIB2_UDP_ENTRY:
			case MIB2_UDP6_ENTRY:
				break;
			default:
				continue;
		}

		// switch over protocol && version
		switch (item->group) {
			case MIB2_TCP:
				if (!opts.v4)
					break;
				if (!opts.p_tcp)
					break;
				for (tp = (mib2_tcpConnEntry_t *)item->valp;
				    (char *)tp < (char *)item->valp + item->length;
				    tp = (mib2_tcpConnEntry_t *)((char *)tp + tcpConnEntrySize)) {
					tcp_report_item_v4(tp);
				}
				break;
			case MIB2_TCP6:
				if (!opts.v6)
					break;
				if (!opts.p_tcp)
					break;
				for (tp6 = (mib2_tcp6ConnEntry_t *)item->valp;
				    (char *)tp6 < (char *)item->valp + item->length;
				    tp6 = (mib2_tcp6ConnEntry_t *)((char *)tp6 + tcp6ConnEntrySize)) {
					tcp_report_item_v6(tp6);
				}
				break;
			case MIB2_UDP:
				if (!opts.v4)
					break;
				if (!opts.p_udp)
					break;
				for (ude = (mib2_udpEntry_t *)item->valp;
				    (char *)ude < (char *)item->valp + item->length;
				    ude = (mib2_udpEntry_t *)((char *)ude + udpEntrySize)) {
					udp_report_item_v4(ude);
				}
				break;
			case MIB2_UDP6:
				if (!opts.v6)
					break;
				if (!opts.p_udp)
					break;
				for (ude6 = (mib2_udp6Entry_t *)item->valp;
				    (char *)ude6 < (char *)item->valp + item->length;
				    ude6 = (mib2_udp6Entry_t *)((char *)ude6 + udp6EntrySize)) {
					udp_report_item_v6(ude6);
				}
		}
	}
	fflush(stdout);
}

static void tcp_report_item_v4(const mib2_tcpConnEntry_t *tp)
{
	print_line(AF_INET, "tcp4", tp->tcpConnCreationProcess,
	    (void *)&tp->tcpConnLocalAddress, tp->tcpConnLocalPort,
	    (void *)&tp->tcpConnRemAddress, tp->tcpConnRemPort);
}

static void tcp_report_item_v6(const mib2_tcp6ConnEntry_t *tp6)
{
	print_line(AF_INET6, "tcp6", tp6->tcp6ConnCreationProcess,
	    (void *)&tp6->tcp6ConnLocalAddress, tp6->tcp6ConnLocalPort,
	    (void *)&tp6->tcp6ConnRemAddress, tp6->tcp6ConnRemPort);
}

static void udp_report_item_v4(const mib2_udpEntry_t *ude) {
	print_line(AF_INET, "udp4", ude->udpCreationProcess,
	    (void *)&ude->udpLocalAddress, ude->udpLocalPort,
	    (void *)&ude->udpEntryInfo.ue_RemoteAddress, ude->udpEntryInfo.ue_RemotePort);
}

static void udp_report_item_v6(const mib2_udp6Entry_t *ude6) {
	print_line(AF_INET6, "udp6", ude6->udp6CreationProcess,
	    (void *)&ude6->udp6LocalAddress, ude6->udp6LocalPort,
	    (void *)&ude6->udp6EntryInfo.ue_RemoteAddress, ude6->udp6EntryInfo.ue_RemotePort);
}

static void print_line(int af, char *proto, int pid, void *lip, uint_t lport, void *rip, uint_t rport) {
	char lname[1024]; // local name
	char rname[1024]; // foreign name

	// check if we should be running
	if (lport == 0)
		return; // not sure why this happens
	if (rport == 0 && !opts.listening)
		return;
	if (rport > 0  && !opts.connected)
		return;
	if (!opts.loopback) {
		switch (af) {
			case AF_INET:
				if (IN_IS_ADDR_LOOPBACK(*(IpAddress *)lip) ||
				    IN_IS_ADDR_LOOPBACK(*(IpAddress *)rip))
					return;
			case AF_INET6:
				if (IN6_IS_ADDR_LOOPBACK((Ip6Address *)lip) ||
				    IN6_IS_ADDR_LOOPBACK((Ip6Address *)rip))
					return;
		}
	}

	char *user = "?";
	char *cmd = "?";
	char *args = "";

	// attempt to get process information
	struct proc_info *info = proc_info_get(pid);
	if (info) {
		cmd = info->psinfo->pr_fname;
		if (opts.args)
			args = info->psinfo->pr_psargs;
		if (info->name)
			user = info->name;
		// TODO else set the user string to the UID
	}

	// format ip:port strings
	// lip_s = local ip string, rip_s = remote ip string
	char lip_s[MAX(INET6_ADDRSTRLEN, INET_ADDRSTRLEN)];
	char rip_s[MAX(INET6_ADDRSTRLEN, INET_ADDRSTRLEN)];
	switch (af) {
		case AF_INET:
			inet_ntop(af, (char *)lip, lip_s, sizeof (lip_s));
			inet_ntop(af, (char *)rip, rip_s, sizeof (rip_s));
			break;
		case AF_INET6:
			inet_ntop(af, lip, lip_s, sizeof (lip_s));
			inet_ntop(af, rip, rip_s, sizeof (rip_s));
			break;
		default:
			fprintf(stderr, "unknown protocol: %d\n", af);
			exit(1);
	}

	// <ip>:<port>
	snprintf(lname, sizeof (lname), "%s:%u", lip_s, lport);
	snprintf(rname, sizeof (rname), "%s:%u", rip_s, rport);

	// this signifies listening socket
	if (rport == 0) {
		strcpy(rname, "*.*");
	}

	char *zonename = "?";
	if (opts.zones && info) {
		zoneid_t zid = info->psinfo->pr_zoneid;
		char zn[ZONENAME_MAX];
		if ((getzonenamebyid(zid, zn, ZONENAME_MAX) != -1))
			zonename = zn;
	}
	if (opts.zones)
		printf(FMT_ZONES, zonename);
	printf(FMT_BODY, user, cmd, pid, proto, lname, rname, args);
}
