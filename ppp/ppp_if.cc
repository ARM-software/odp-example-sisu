/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#define __STDC_FORMAT_MACROS
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "ppp_graph.h"
#include "ppp_if.h"
#include "ppp_packet.h"
#include "ppp_pktpool.h"
#include "pkt_hdrs.h"

//Ethernet encapsulated packet
void
ppp_if::input_eth_pkt(ppp_packet *pkt)
{
    //Check for unicast destination address
    const ethhdr *eth = static_cast<const ethhdr *>(pkt->data_ptr());
    enum pb_lladdr addr_type;
    if (likely(eth->is_unicast()))
    {
	const uint16_t *m = (const uint16_t *)macaddr;

	//Check for MAC address of interface
	if (likely(eth->dstaddr[0] == m[0] &&
		   eth->dstaddr[1] == m[1] &&
		   eth->dstaddr[2] == m[2]))
	{
	    addr_type = PPP_LLADDR_THISHOST;
	}
	else
	{
	    addr_type = PPP_LLADDR_OTHERHOST;
	}
    }
    else//Broadcast/multicast address
    {
	if ((eth->dstaddr[0] & eth->dstaddr[1] & eth->dstaddr[2]) == 0xffff)
	{
	    addr_type = PPP_LLADDR_BROADCAST;
	}
	else
	{
	    addr_type = PPP_LLADDR_MULTICAST;
	}
    }
    pkt->lladdr_set(addr_type);

    ppp_if::input_raw_pkt(pkt);
}

//Unencapsulated packet, e.g. raw IP
void
ppp_if::input_raw_pkt(ppp_packet *pkt)
{
    //Are we supposed to receive this packet?
    if (likely(pkt->lladdr() != PPP_LLADDR_OTHERHOST ||
	       promcnt.get() > 0))
    {
	//Pretend packet originates from this interface
	pkt->ifindex_set(ifx);
	stats.rx.pkts.add(1);
	stats.rx.bytes.add(pkt->length());
	if (likely((pkt->ipv4_good())))
	{
	    ipv4good.enter(pkt);//IPv4 with correct csum and valid total_len
	}
	else
	{
	    deliver.enter(pkt);//Any type of frame
	}
    }
    else//Destined to otherhost and interface not in promiscuous mode
    {
	discard.enter(pkt);
    }
}

void ppp_if::verify_ipv4_csum(ppp_packet *pkt)
{
    ipv4hdr *iphdr = pkt->get_ipv4hdr();
    //Check if we have IP header in first segment
    if (likely(pkt->seglen() >= IPv4HDR_MIN_SIZE &&
	       pkt->seglen() >= iphdr->hdr_size()))
    {
	//Verify header checksum
	uint16_t csum = iphdr->checksum();
	//iphdr checksum may be 0 for locally captured packets with
	//offloaded checksumming
	if (unlikely(iphdr->hchecksum == 0 && allow_zero))
	{
	    //Patch in the correct header checksum
	    iphdr->hchecksum = csum;
	    //Recompute checksum
	    assert(iphdr->checksum() == 0);
	    csum = 0;
	}
	if (likely(csum == 0))
	{
	    //TODO verify ipv4->total_len
	    pkt->ipv4_good_set(true);
	}
    }
}

ppp_if::ppp_if(ppp_graph *_graph,
	       const char *_name,
	       ppp_ifindex_t _ifx,
	       ppp_edgeP_f if_transmit) :
	    ppp_module(_graph, _name, "interface"),
	    ifx(_ifx),
	    iftype(PPP_IFTYPE_LOOPBACK),
	    macaddrlen(0),
	    llhdrsize(0),
	    mtu(0),
	    vlan_tci(0),
	    hwcap(0),
	    admstate(0),
	    allow_zero(false),
	    transmit("transmit", this, if_transmit),
	    deliver("deliver", this),
	    ipv4good("ipv4good", this, PROP_IPv4|PROP_IPv4GOOD),
	    discard("discard", this)
{
    memset(macaddr, 0, macaddrlen);
    ipv4.addr = 0;
    ipv4.mask = 0;
    stats.rx.pkts = 0;
    stats.rx.bytes = 0;
    stats.tx.pkts = 0;
    stats.tx.bytes = 0;
    graph->add_if(this, ifx);
}

ppp_if::~ppp_if()
{
    graph->if_array[ifx] = NULL;
}

void
ppp_if::return_pkt(ppp_packet *pkt)
{
    //If someone returns a packet to us, just free it
    if (pkt->is_counting())
    {
	pkt->cycles_end();
    }
    pkt->free();
}

void
ppp_if::traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *handle)
{
    apply(handle, this, &deliver);
    apply(handle, this, &ipv4good);
    apply(handle, this, &discard);
}

void
ppp_if::set_ipv4(uint32_t addr, uint32_t mask)
{
    ipv4.addr = addr;
    ipv4.mask = mask;
}

void
ppp_if::set_macaddr(unsigned char _macaddr[], uint32_t _macaddrlen)
{
    if (macaddrlen > MAXADDRLEN)
    {
	fprintf(stderr, "%s: Too long MAC address\n", name);
	abort();
    }
    if ((iftype & PPP_IFTYPE_MASK) != PPP_IFTYPE_ETHERNET)
    {
	return;
    }
    if (_macaddrlen != MAC48LEN)
    {
	fprintf(stderr, "%s: Invalid MAC address length %u for Ethernet "
		"interface\n", name, _macaddrlen);
	abort();
    }
    memcpy(macaddr, _macaddr, (macaddrlen = _macaddrlen));
}

void
ppp_if::set_promiscuous(bool enable)
{
    if (enable)
    {
	promcnt.add(1);
    }
    else if (promcnt.get() > 0)
    {
	promcnt.add(-1);
    }
    //Else ignore
}

#define IP2NdNdNdN(x) (x) >> 24, ((x) >> 16) & 0xff, ((x) >> 8) & 0xff, (x) & 0xff

void ppp_if::print_if_hdr()
{
    fprintf(stderr,
"Ifx MAC-address	     MTU  IPv4-address       #RX    #TX Name\n");
}

void ppp_if::print_if(unsigned i)
{
    unsigned j;
    char buf[20];
    buf[0] = 0;
    if (ipv4.addr != 0)
    {
	uint32_t addr = ipv4.addr;
	sprintf(buf, "%u.%u.%u.%u", IP2NdNdNdN(addr));
    }
    fprintf(stderr, "%3u ", i);
    for (j = 0; j < macaddrlen; j++)
    {
	fprintf(stderr, "%02x%c", macaddr[j],
		j + 1 < macaddrlen ? ':' : ' ');
    }
    for (;j < MAXADDRLEN; j++)
    {
	fprintf(stderr, "   ");
    }
    fprintf(stderr, "%4u %-15s %6" PRIu64" %6" PRIu64" %s\n",
	    mtu, buf, stats.rx.pkts.get(),
	    stats.tx.pkts.get(), name);
}

static inline void
copy_mac48addr(unsigned char dst[], const unsigned char src[])
{
    const uint16_t *srcw = (const uint16_t *)src;
    uint16_t *dstw = (uint16_t *)dst;
    uint16_t a, b, c;
    a = srcw[0];
    b = srcw[1];
    c = srcw[2];
    dstw[0] = a;
    dstw[1] = b;
    dstw[2] = c;
}

#define IFTYPE_ETH(iftype) (((iftype) & PPP_IFTYPE_MASK) == PPP_IFTYPE_ETHERNET)
#define IFTYPE_TUN(iftype) (((iftype) & PPP_IFTYPE_MASK) == PPP_IFTYPE_IPTUNNEL)
//#define IFTYPE_VLAN(iftype) (((iftype) & PPP_IFTYPE_VLAN) != 0)

void
ppp_if::init_pkt_hdr(ppp_packet *pkt,
		     const unsigned char dstaddr[],
		     uint16_t frametype)
{
    if (likely(IFTYPE_ETH(iftype)))
    {
	ethhdr *ethhdr = static_cast<struct ethhdr *>(pkt->grow_head(llhdrsize));
	uint32_t hdrsize = sizeof(struct ethhdr);
	static const unsigned char brdcstaddr[6] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	copy_mac48addr(ethhdr->dstaddr, dstaddr ? dstaddr : brdcstaddr);
	copy_mac48addr(ethhdr->srcaddr, macaddr);
	if (unlikely(vlan_tci != 0)) //vlanid or priority set
	{
	    ethhdr->frametype = htons(PPP_FRAMETYPE_VLAN);
	    vlantag *vlan = (vlantag *)(ethhdr + 1);
	    vlan->vlan_tci  = vlan_tci;
	    vlan->frametype = htons(frametype);
	    hdrsize += sizeof(struct vlantag);
	}
	else //Plain Ethernet interface with priority 0 packets
	{
	    ethhdr->frametype = htons(frametype);
	}
	//Leave pkt->length and pkt->headroom as is
	pkt->hdrsize_set(hdrsize);
	pkt->framing_set(PPP_FRAMING_ETHERNET);
	pkt->protocol_set(frametype);
    }
    else if (likely(IFTYPE_TUN(iftype)))
    {
	pkt->framing_set(PPP_FRAMING_NONE);
	pkt->protocol_set(frametype);
    }
}
