/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _CAPIF_H
#define _CAPIF_H

#include <stdio.h>
#include <pcap/pcap.h>
#include "ppp_if.h"
#include "odp.h"

class ppp_pktpool;

#define NUM_REMOTE 32

class capif : public ppp_if
{
    //Input
    ppp_pktpool *pool;
    FILE *fp;
    pcap_t *pf;
    uint32_t linktype;
    //Output
	uint32_t tx_linktype;
    bool loopback;
    pcap_dumper_t *pd;
    bool discard_inb;
    unsigned num_remote;
    uint32_t remote_ip[NUM_REMOTE];//IP addresses of remote nodes

    odp_ticketlock_t lock;
public:

    capif(ppp_graph *, const char *_name, ppp_ifindex_t _ifx, ppp_pktpool *_pool, const char *pcap_input, const char *pcap_output, uint32_t linktype, bool loopback);
    ~capif();

    virtual void transmit_pkt(ppp_packet *);
    virtual void traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *);
    virtual void sd_handler(int sd, int poll_handler);
    virtual void set_promiscuous(bool enable);
    void discard_inbound(bool enable);
};

#endif //_CAPIF_H
