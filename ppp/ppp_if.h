/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

//Packet Processing Pipeline - base class for network interfaces
#ifndef _PPP_IF_H
#define _PPP_IF_H

#include "stdatomic.h"
#include "ppp_module.h"
#include "ppp_edge.h"
#include "pkt_hdrs.h"

#define PPP_INDEX_INVALID 0
typedef int32_t ppp_ifindex_t;

typedef enum
{
    PPP_IFTYPE_LOOPBACK = 0x00000000,
    PPP_IFTYPE_IPTUNNEL = 0x00000001,
    PPP_IFTYPE_ETHERNET = 0x00000002,
    PPP_IFTYPE_MASK     = 0x0000FFFFU
} ppp_iftype_t;

class ppp_if : public ppp_module
{
public:
    const ppp_ifindex_t ifx;
    ppp_iftype_t iftype;
    unsigned char macaddr[MAXADDRLEN];
    uint16_t macaddrlen;
    uint16_t llhdrsize;
    uint16_t mtu; //Max payload size, excluding any link layer header(s)
    uint16_t vlan_tci; //Must know this for pkt header initialization
    uint32_t hwcap;
    atomic_uint32 admstate;
    atomic_uint32 promcnt;
    struct
    {
	struct
	{
	    atomic_uint64 pkts;
	    atomic_uint64 bytes;
	} rx;
	struct
	{
	    atomic_uint64 pkts;
	    atomic_uint64 bytes;
	} tx;
    } stats;
    struct //IPv4 address and subnet mask
    {
	uint32_t addr;
	uint32_t mask;
    } ipv4;
    bool allow_zero;//Allow zero IPv4 header checksum (e.g. from packet capture
		    //with HW-offloaded checksumming)

    //Default inputs and outputs
    ppp_inputP transmit;
    ppp_outputP deliver;
    ppp_outputP ipv4good; //Output for IPv4 pkts with valid header checksum
    ppp_outputP discard;

    ppp_if(ppp_graph *,
	   const char *_name,
	   ppp_ifindex_t _ifx,
	   ppp_edgeP_f if_input);
    ~ppp_if();
    void input_eth_pkt(ppp_packet *);
    void input_raw_pkt(ppp_packet *);
    void verify_ipv4_csum(ppp_packet *);//Set IPV4_GOOD in pkt->parserflags
    virtual void transmit_pkt(ppp_packet *) = 0;
    virtual void return_pkt(ppp_packet *);
    virtual void traverse_outputs(void (*apply)(void *,
						ppp_module *,
						ppp_output *),
				   void *);

    //Use dstaddr == NULL for broadcast address
    virtual void init_pkt_hdr(ppp_packet *pkt,
			      const unsigned char dstaddr[],
			      uint16_t frametype);

    void set_ipv4(uint32_t addr, uint32_t mask);
    virtual void set_macaddr(unsigned char macaddr[], uint32_t macaddrlen);
    virtual void set_promiscuous(bool enable);
    void allow_zero_chksum(bool enable);

    void print_if(unsigned);

    //Shared helpers
    static void print_if_hdr();
};

#endif //_PPP_IF_H
