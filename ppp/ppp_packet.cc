/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

//Implementation of generic pktbuf utilities

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "ppp_packet.h"
#include "ppp_pktpool.h"
#include "compiler.h"
#include "stdatomic.h"
#include "ppp_graph.h"
#include "ppp_if.h"
#include "pkt_hdrs.h"

#define IP2NdNdNdN(x) (x) >> 24, ((x) >> 16) & 0xff, ((x) >> 8) & 0xff, (x) & 0xff

static inline uint32_t min(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static const char *
frtype2str(uint16_t frametype)
{
    switch (frametype)
    {
	//Incomplete list of frametypes
	case PPP_FRAMETYPE_ARP :
	    return "ARP";
	case PPP_FRAMETYPE_IPV4 :
	    return "IPv4";
	case PPP_FRAMETYPE_IPV6 :
	    return "IPv6";
	case PPP_FRAMETYPE_VLAN :
	    return "VLAN";
	default :
	    return "?";
    }
}

static const char *
ippr2str(uint8_t ip_proto)
{
    switch (ip_proto)
    {
	//Incomplete list of IP subprotocols
	case PPP_IPPROTO_ICMP :
	    return "ICMP";
	case PPP_IPPROTO_IGMP :
	    return "IGMP";
	case PPP_IPPROTO_TCP :
	    return "TCP";
	case PPP_IPPROTO_UDP :
	    return "UDP";
	case PPP_IPPROTO_SCTP :
	    return "SCTP";
	case PPP_IPPROTO_ESP :
	    return "ESP";
	case PPP_IPPROTO_AH :
	    return "AH";
	case PPP_IPPROTO_GRE :
	    return "GRE";
	default :
	    return "?";
    }
}

static const char *
icmp_type2str(uint8_t type)
{
    switch (type)
    {
	//Incomplete list of ICMP types
	case ICMP_TYPE_ECHOR :
	    return "echo reply";
	case ICMP_TYPE_DESTINATION_UNREACHABLE :
	    return "destination unreachable";
	case ICMP_TYPE_REDIRECT_MESSAGE :
	    return "redirect";
	case ICMP_TYPE_ECHO :
	    return "echo request";
	case ICMP_TYPE_TIME_EXCEEDED :
	    return "time exceeded";
	case ICMP_TYPE_PARAMETER_PROBLEM :
	    return "parameter problem";
	default :
	    return "?";
    }
}

static const char *
icmp_code2str(uint8_t code, uint8_t type)
{
    return "?"; //TODO: implement icmp_code2str()
}

static void
dump_data(const char *prefix, const void *ptr, uint32_t dumplen)
{
    const uint8_t *data = (const uint8_t *)ptr;
    uint32_t i;
    for (i = 0; i < dumplen; i++)
    {
	if (i % 16 == 0)
	{
	    printf("%s%2u:", prefix, i);
	}
	printf(" %02x", data[i]);
	if (i % 16 == 15)
	{
	    printf("\n");
	}
    }
    if (i % 16 != 0)
    {
	printf("\n");
    }
}

static const char *
typeofmacaddress(const uint8_t *macaddr, ppp_ifindex_t ifx, ppp_graph *graph)
{
    if ((macaddr[0] & 1) == 0)
    {
	if ((macaddr[0] | macaddr[1] | macaddr[2] |
	     macaddr[3] | macaddr[4] | macaddr[5]) == 0x00)
	{
	    return "null";
	}
	else if (graph == NULL || ifx == PPP_INDEX_INVALID)
	{
	    return "somehost";
	}
	else if (memcmp(graph->if_array[ifx]->macaddr, macaddr, MAC48LEN) == 0)
	{
	    return "thishost";
	}
	else
	{
	    return "otherhost";
	}
    }
    else if ((macaddr[0] & macaddr[1] & macaddr[2] &
	      macaddr[3] & macaddr[4] & macaddr[5]) == 0xff)
    {
	return "broadcast";
    }
    else
    {
	return "multicast";
    }
}

static const char *
arp_opcode2str(uint16_t opcode)
{
    switch (opcode)
    {
	case ARP_OPCODE_REQUEST :
	    return "request";
	case ARP_OPCODE_RESPONSE :
	    return "response";
	default :
	    return "?";
    }
}

void ppp_packet::dump(ppp_graph *graph, uint32_t flags) const
{
    const ppp_packet *pkt = this;
    static const char * const lladdr[] =
    {
	"thishost", "otherhost", "multicast", "broadcast"
    };
    static const char * const framing[] =
    {
	"none", "", "", "", "ethernet"
    };
    char Flags[17];

    memset(Flags, '.', 16);
    Flags[16] = 0;

    if ((flags & PPP_DUMP_BUFFER) != 0)
    {
    printf("ppp.packet @ %p\n", pkt);
    printf("ppp.temp........: %u/%#x\n", pkt->temp, pkt->temp);
    printf("ppp.flags.......: %s\n", Flags);

    printf("ppp.data_ptr....: %p\n", pkt->data_ptr());
    printf("ppp.seglen......: %u/%#x\n", pkt->seglen(), pkt->seglen());
    printf("ppp.length......: %u/%#x\n", pkt->length(), pkt->length());
    printf("ppp.headroom....: %d/%#x\n", pkt->headroom(), pkt->headroom());

    //Assume these fields are valid
    {
    printf("ppp.ifindex.....: %d %s\n", pkt->ifindex(),
	   graph ? graph->ifx2name(pkt->ifindex()) : "");
    printf("ppp.parserflags.: %u/%#x\n", pkt->parserflags(), pkt->parserflags());
    //TODO decode h_parserflags
    printf("ppp.ll-address..: %s\n", lladdr[pkt->lladdr()]);
    printf("ppp.framing.....: %s\n", framing[pkt->framing()]);
    printf("ppp.hdrsize.....: %d\n", pkt->hdrsize());
    printf("ppp.protocol....: %#x %s\n", pkt->protocol(),
	   frtype2str(pkt->protocol()));
    printf("ppp.context.....: %p\n", pkt->context());
    }

    printf("ppp.nextpkt.....: %p\n", pkt->nextpkt());
    printf("ppp.spareptr...: %p\n", pkt->spareptr());
    }

    const void *ptr = static_cast<const void *>(pkt->data_ptr());
    if ((flags & PPP_DUMP_RAWDUMP) != 0)
    {
	dump_data("", ptr, pkt->seglen() < 96 ? pkt->seglen() : 96);
    }
    if ((flags & PPP_DUMP_L2HDR) != 0 &&
	pkt->framing() == PPP_FRAMING_ETHERNET)
    {
	const ethhdr *eth = static_cast<const ethhdr *>(ptr);
	printf("eth.dstaddr..: %02x:%02x:%02x:%02x:%02x:%02x %s\n",
		eth->dstaddr[0], eth->dstaddr[1], eth->dstaddr[2],
		eth->dstaddr[3], eth->dstaddr[4], eth->dstaddr[5],
		typeofmacaddress(eth->dstaddr, pkt->ifindex(), graph));
	printf("eth.srcaddr..: %02x:%02x:%02x:%02x:%02x:%02x %s\n",
		eth->srcaddr[0], eth->srcaddr[1], eth->srcaddr[2],
		eth->srcaddr[3], eth->srcaddr[4], eth->srcaddr[5],
		typeofmacaddress(eth->srcaddr, pkt->ifindex(), graph));
	printf("eth.frametype: %#x %s\n", ntohs(eth->frametype),
	       frtype2str(ntohs(eth->frametype)));
	if (eth->frametype == htons(PPP_FRAMETYPE_VLAN))
	{
	    const vlantag *vlan = (const vlantag *)(eth + 1);
	printf("vlan.pri......: %u\n", (ntohs(vlan->vlan_tci) >> 13) & 0x7);
	printf("vlan.id.......: %u\n", ntohs(vlan->vlan_tci) & 0xfff);
	printf("vlan.frametype: %#x %s\n", ntohs(vlan->frametype),
	       frtype2str(ntohs(vlan->frametype)));
	}
    }
    if (pkt->protocol() == PPP_FRAMETYPE_ARP)
    {
	if ((flags & PPP_DUMP_ARP) != 0)
	{
	    const arppkt *arp = static_cast<const arppkt *>(pkt->payload_ptr());
	    printf("arp.opcode.....: %u %s\n", ntohs(arp->opcode),
		   arp_opcode2str(ntohs(arp->opcode)));
	    printf("arp.snd_hw_addr: %02x:%02x:%02x:%02x:%02x:%02x %s\n",
		    arp->snd_hw_addr[0], arp->snd_hw_addr[1],
		    arp->snd_hw_addr[2], arp->snd_hw_addr[3],
		    arp->snd_hw_addr[4], arp->snd_hw_addr[5],
		    typeofmacaddress(arp->snd_hw_addr, pkt->ifindex(), graph));
	    printf("arp.snd_ip_addr: %u.%u.%u.%u\n",
		    arp->snd_ip_addr[0], arp->snd_ip_addr[1],
		    arp->snd_ip_addr[2], arp->snd_ip_addr[3]);
	    printf("arp.tgt_hw_addr: %02x:%02x:%02x:%02x:%02x:%02x %s\n",
		    arp->tgt_hw_addr[0], arp->tgt_hw_addr[1],
		    arp->tgt_hw_addr[2], arp->tgt_hw_addr[3],
		    arp->tgt_hw_addr[4], arp->tgt_hw_addr[5],
		    typeofmacaddress(arp->tgt_hw_addr, pkt->ifindex(), graph));
	    printf("arp.tgt_ip_addr: %u.%u.%u.%u\n",
		    arp->tgt_ip_addr[0], arp->tgt_ip_addr[1],
		    arp->tgt_ip_addr[2], arp->tgt_ip_addr[3]);
	}
    }
    else if (pkt->protocol() == PPP_FRAMETYPE_IPV4)
    {
	const ipv4hdr *ipv4 = pkt->get_ipv4hdr();
	uint16_t payload_len = ipv4->payload_len();
	if ((flags & PPP_DUMP_IPHDR) != 0)
	{
	    uint32_t srcaddr = ntohl(ipv4->src_addr);
	    uint32_t dstaddr = ntohl(ipv4->dst_addr);
	    printf("ipv4.tos......: %u\n", ipv4->tos);
	    printf("ipv4.ttl......: %u\n", ipv4->ttl);
	    printf("ipv4.total_len: %u\n", ntohs(ipv4->total_len));
	    if (ipv4->is_frag())
	    {
	    printf("ipv4.frag_offs: %u\n", ipv4->frag_offset());
	    printf("ipv4.frag_more: %s\n", ipv4->frag_more() ? "more" : "last");
	    }
	    printf("ipv4.ip_proto.: %u %s\n", ipv4->ip_proto,
					      ippr2str(ipv4->ip_proto));
	    printf("ipv4.hchecksum: %#04x %s\n", ntohs(ipv4->hchecksum),
		   ipv4->checksum() == 0 ? "good" : "bad");
	    printf("ipv4.src_addr.: %u.%u.%u.%u\n", IP2NdNdNdN(srcaddr));
	    printf("ipv4.dst_addr.: %u.%u.%u.%u\n", IP2NdNdNdN(dstaddr));
	}
	if (!ipv4->is_frag() || ipv4->frag_offset() == 0)
	{
	    //First or only fragment
	    if (ipv4->ip_proto == PPP_IPPROTO_UDP &&
		payload_len >= sizeof(udphdr))
	    {
		const udphdr *udp = ipv4->get_udphdr();
		unsigned udp_length = ntohs(udp->length);
		if ((flags & PPP_DUMP_IPL4HDR) != 0)
		{
		    const char *csum_status;
		    printf("udp.src_port: %u\n", ntohs(udp->src_port));
		    printf("udp.dst_port: %u\n", ntohs(udp->dst_port));
		    printf("udp.length..: %u\n", udp_length);
		    if (udp_length >= sizeof(udphdr))
		    {
			if (udp->chksum != 0)
			{
			    uint16_t csum = udp->checksum(udp->payload_ptr());
			    if (csum == 0xffff)
			    {
				csum_status = "good";
			    }
			    else
			    {
				printf("udp.computed_sum: 0x%x\n", csum);
				csum_status = "bad";
			    }
			}
			else
			{
			    csum_status = "no checksum";
			}
		    }
		    else
		    {
			csum_status = "UDP header corrupt";
		    }
		    printf("udp.checksum: %#04x %s\n", ntohs(udp->chksum), csum_status);
		}
		if ((flags & PPP_DUMP_IPL4DATA) != 0)
		{
		    dump_data("udp.data ", udp->payload_ptr(),
			      min(udp->payload_len(), 64));
		}
	    }
	    else if (ipv4->ip_proto == PPP_IPPROTO_TCP &&
		     payload_len >= sizeof(tcphdr))
	    {
		const tcphdr *tcp = ipv4->get_tcphdr();
		if ((flags & PPP_DUMP_IPL4HDR) != 0)
		{
		    char flags[13];
		    printf("tcp.src_port: %u\n", ntohs(tcp->src_port));
		    printf("tcp.dst_port: %u\n", ntohs(tcp->dst_port));
		    memset(flags, '.', sizeof flags);
		    flags[sizeof flags - 1] = 0;
		    uint16_t tcp_flags = ntohs(tcp->flags);
		    if (tcp_flags & TCP_FLAG_FIN) flags[11] = 'F';
		    if (tcp_flags & TCP_FLAG_SYN) flags[10] = 'S';
		    if (tcp_flags & TCP_FLAG_RST) flags[ 9] = 'R';
		    if (tcp_flags & TCP_FLAG_PSH) flags[ 8] = 'P';
		    if (tcp_flags & TCP_FLAG_ACK) flags[ 7] = 'A';
		    if (tcp_flags & TCP_FLAG_URG) flags[ 6] = 'U';
		    if (tcp_flags & TCP_FLAG_ECE) flags[ 5] = 'E';
		    if (tcp_flags & TCP_FLAG_CWR) flags[ 4] = 'C';
		    if (tcp_flags & TCP_FLAG_NS ) flags[ 3] = 'N';
		    if (tcp_flags & TCP_FLAG_RS0) flags[ 2] = '1';
		    if (tcp_flags & TCP_FLAG_RS1) flags[ 1] = '1';
		    if (tcp_flags & TCP_FLAG_RS2) flags[ 0] = '1';
		    printf("tcp.flags.......: %s\n", flags);
		    printf("tcp.seqno.......: %u\n", ntohl(tcp->seqno));
		    printf("tcp.ackno.......: %u (ACK is %s)\n",
			   ntohl(tcp->ackno),
			   (tcp_flags & TCP_FLAG_ACK) ? "set" : "clear");
		    printf("tcp.winsz.......: %u\n", ntohs(tcp->winsz));
		    printf("tcp.urgptr......: %u (URG is %s)\n",
			   ntohl(tcp->urgptr),
			   (tcp_flags & TCP_FLAG_URG) ? "set" : "clear");
		    uint16_t csum = tcp->checksum(tcp->payload_ptr(),
						  ipv4->payload_len() -
						  tcp->hdr_size());
		    const char *csum_status;
		    if (csum == 0xffff || csum == 0)//???
		    {
			csum_status = "good";
		    }
		    else
		    {
			printf("tcp.computed_sum: 0x%x\n", csum);
			csum_status = "bad";
		    }
		    printf("tcp.checksum...: %#04x %s\n", ntohs(tcp->chksum), csum_status);
		}
		if ((flags & PPP_DUMP_IPL4DATA) != 0)
		{
		    //TODO print TCP payload
		}
	    }
	    else if (ipv4->ip_proto == PPP_IPPROTO_ICMP &&
		     payload_len >= sizeof(icmphdr))
	    {
		uint32_t nbytes = ipv4->hdr_size();
		icmphdr *icmp = ipv4->get_icmphdr();
		uint32_t ip_total_len = ntohs(ipv4->total_len);
		uint32_t icmp_total_len = ip_total_len - nbytes;
		if ((flags & PPP_DUMP_IPL4HDR) != 0)
		{
		    const char *csum_status;
		    printf("icmp.type....: %u %s\n", icmp->type,
			   icmp_type2str(icmp->type));
		    printf("icmp.code....: %u %s\n", icmp->code,
			   icmp_code2str(icmp->code, icmp->type));
		    if (icmp_total_len >= sizeof(icmphdr))
		    {
			//TODO ICMP checksum not computed correctly
			uint16_t csum = ~icmp->checksum(icmp_total_len);
			if (csum == 0)
			{
			    csum_status = "good";
			}
			else
			{
			    printf("icmp.computed_sum: 0x%x\n", csum);
			    csum_status = "bad";
			}
		    }
		    else
		    {
			csum_status = "ICMP datagram truncated";
		    }
		    printf("icmp.checksum: %#04x %s\n", ntohs(icmp->chksum),
			    csum_status);
		    if (icmp->type == ICMP_TYPE_ECHO ||
			icmp->type == ICMP_TYPE_ECHOR);
		    {
		    printf("icmp.ident...: %u\n", ntohs(icmp->ident));
		    printf("icmp.seqno...: %u\n", ntohs(icmp->seqno));
		    }
		}
		if ((flags & PPP_DUMP_IPL4DATA) != 0)
		{
		    uint32_t data_len = icmp_total_len - sizeof(icmphdr);
		    printf("icmp.datalen.: %u\n", data_len);
		    dump_data("icmp.data ", (uint8_t*)icmp + sizeof(icmphdr), data_len);
		}
	    }
	    //Else unknown IP protocol or too little data present
	}
	else//Non-first fragment, don't know what IP protocol
	{
	    if ((flags & PPP_DUMP_IPL4HDR) != 0)
	    {
		dump_data("ipv4.payload..:", ipv4->payload_ptr(),
			  payload_len < 64 ? payload_len : 64);
	    }
	}
    }
    fflush(stdout);
}
