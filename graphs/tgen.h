/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _TGEN_H
#define _TGEN_H

#include <stdio.h>
#include "../ppp/ppp_if.h"
#include "../ppp/odp_sink.h"
#include "../ppp/ppp_graph.h"
#include "odp.h"

#ifdef SISU_ACCOUNTING
#define TGEN_NSTAGES 2

#define TGEN_STAGE_DESCS \
"Packet allocation",	 \
"Packet generation",

#define TGEN_FIELDS	\
TGEN_PACKET_ALLOCATION, \
TGEN_PACKET_GENERATION,
#endif

class bearer_context;
class ppp_pktpool;

// Bearer context - used for egress traffic
struct tgen_bearer_context {
	odp_queue_t queue;
};

class tgen_if : public ppp_if
{
	int sd;
	volatile bool _stop;
	ppp_pktpool *pool;

	std::list<bearer_context *> _ctx_list;
	std::list<bearer_context *>::iterator _ctx_it;
	odp_rwlock_t rwlock; // TODO remove lock

	friend class tgen;

public:
	tgen_if(ppp_graph *,
		const char *_name,
		ppp_ifindex_t _ifx,
		ppp_pktpool *_pool);
	~tgen_if();

	virtual void transmit_pkt(ppp_packet *);
	virtual void traverse_outputs(void (*apply)(void *,
						    ppp_module *,
						    ppp_output *),
				      void *);
	virtual void sd_handler(int sd, int poll_handler);
};

class tgen : public ppp_graph
{
	odp_sink *_sink;
	tgen_if *_tgen_if;

public:
	tgen(const char *name, ppp_pktpool *pktpool);
	~tgen();

	void stop();
	void start_flow(bearer_context *ctx);
	void stop_flow(bearer_context *ctx);
};
#endif //_TGEN_H
