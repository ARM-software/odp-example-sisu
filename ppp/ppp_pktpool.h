/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

//PPP packet pool API

#ifndef _PPP_PKTPOOL_H
#define _PPP_PKTPOOL_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "stdatomic.h"
#include "compiler.h"
#include "ppp_packet.h"
#include "odp.h"

class ppp_pktpool
{
    odp_pool_t poolh;
    uint16_t hdroom;

public:
    ppp_pktpool(const char *_name, uint32_t _numpkts, uint16_t _hdroom, uint16_t _maxsize)
    {
	odp_pool_param_t params;
		odp_pool_param_init(&params);
	params.pkt.seg_len = sizeof(ppp_packet) + _hdroom + _maxsize;
	params.pkt.len     = params.pkt.seg_len;
	params.pkt.num     = _numpkts;
	params.type	   = ODP_POOL_PACKET;
	poolh = odp_pool_create(_name, &params);
	if (poolh == ODP_POOL_INVALID)
	    perror("odp_pool_create"), exit(EXIT_FAILURE);
	hdroom = _hdroom;
    }
    ~ppp_pktpool()
    {
	odp_pool_destroy(poolh);
    }

    //A pktpool is a packet factory so let's make some packets
    ppp_packet *alloc_pkt(uint32_t size, odp_queue_t queue)
    {
	odp_packet_t pkth = odp_packet_alloc(poolh, 1);
	if (unlikely(pkth == ODP_PACKET_INVALID))
	{
	    return NULL;
	}
	assert(odp_packet_len(pkth) == 0);
	ppp_packet *pkt = static_cast<ppp_packet *>(odp_packet_head(pkth));
	pkt->init(pkth, queue);
#ifdef SISU_DEBUG
		pkt->log_alloc();
#endif
	return pkt;
    }

    inline odp_pool_t odp_pool()
    {
	return poolh;
    }
};

#endif /* _PPP_PKTPOOL_H */
