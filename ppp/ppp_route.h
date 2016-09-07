/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _PPP_ROUTE_H
#define _PPP_ROUTE_H

#include <stdint.h>
#include <string.h>
#include "pkt_hdrs.h"
#include "lpm.h"

enum rt_type
{
//'dest' matches host/network
//Action: block (prohibited/unreachable/blackhole), discard packet, optionally
//return ICMP error message
    rt_block = 0,
//'dest' matches IP address of interface 'ifx'
//Action: deliver packet locally on matching (or ingress)? interface
    rt_this = 1,
//'dest' matches host or network on interface 'ifx' ("directly attached")
//Action: lookup MAC address and transmit packet on specified interface
    rt_local = 2,
//'dest' matches remote host/network reachable through 'gway' on interface 'ifx'
//Action: Forward packet to specified gateway
    rt_remote = 3,
//'dest' matches multicast address
//Action: multicast handling...
    rt_mcast = 4
};

class ppp_route: public prefix
{
public:
    uint32_t ifx;
    uint32_t gway;//IPv4 address of gateway (if type == rt_remote)
    enum rt_type type:8;
    uint8_t macaddrlen;//length of gateway MAC address
    unsigned char macaddr[MAXADDRLEN];//gateway MAC address

    ppp_route(uint32_t _dest,
	      uint8_t _len,
	      enum rt_type _type,
	      uint32_t _ifx,
	      uint32_t _gw,
	      uint16_t _maclen,
	      unsigned char *_macaddr) :
	prefix(_dest, _len),
	ifx(_ifx),
	gway(_gw),
	type(_type),
	macaddrlen(_maclen)
    {
	if (macaddrlen != 0)
	{
	    memcpy(macaddr, _macaddr, macaddrlen);
	}
    }
};

class ppp_rib: public prefix_tree
{
public:
    ppp_rib()
    {
	prefix_tree();
    }
    void add_route(ppp_route *rt)
    {
	add_prefix(rt);
    }
    ppp_route *find_lpm(uint32_t addr)
    {
	return static_cast<ppp_route *>(prefix_tree::find_lpm(addr));
    }
};

#endif //_PPP_ROUTE_H
