/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _ODP_SINK_H
#define _ODP_SINK_H

#include <list>

#include "ppp_module.h"
#include "ppp_edge.h"

#include "odp.h"

#ifdef SISU_ACCOUNTING
#define ODP_SINK_NSTAGES 7

#define ODP_SINK_STAGE_DESCS	\
"Packet sent to RR queue",		\
"Packet sent to fixed queue",	\
"Packet sent to queue in packet",\
"Packet freed",			\
"Whole SISU on egress",		\
"Whole SISU on ingress",        \
"Whole system",

#define ODP_SINK_FIELDS		\
ODP_SINK_RR_SENT,		\
ODP_SINK_FIXED_SENT,		\
ODP_SINK_PACKET_SENT,		\
ODP_SINK_PACKET_FREED,		\
ODP_SINK_WHOLE_EGRESS,		\
ODP_SINK_WHOLE_INGRESS,         \
ODP_SINK_WHOLE_SYSTEM,
#endif

class ppp_packet;

class odp_sink : public ppp_module
{
public:
	ppp_inputP input;
	struct {
		struct {
			atomic_uint64 pkts;
			atomic_uint64 bytes;
		} enq;
		struct{
			atomic_uint64 pkts;
			atomic_uint64 bytes;
		} free;
	} stats;

	odp_sink(ppp_graph *, const char *_name);
	~odp_sink();

	virtual void input_pkt(ppp_packet *);
	virtual void traverse_outputs(void (*apply)(void *,
						    ppp_module *,
						    ppp_output *),
				      void *);
};

class odp_sink_rr : public odp_sink
{
	std::list<odp_queue_t> _queue_list;
	std::list<odp_queue_t>::iterator _queue_it;
	odp_rwlock_t rwlock; // TODO remove lock

public:
	odp_sink_rr(ppp_graph *, const char *_name);
	~odp_sink_rr();

	void register_queue(odp_queue_t queue);
	void deregister_queue(odp_queue_t queue);

	virtual void input_pkt(ppp_packet *);
};

class odp_sink_fixed : public odp_sink
{
	odp_queue_t _fixed_queue;

public:
	odp_sink_fixed(ppp_graph *, const char *_name);
	~odp_sink_fixed();

	void set_fixed_queue(odp_queue_t queue);

	virtual void input_pkt(ppp_packet *);
};

class odp_sink_pktio : public odp_sink
{
	odp_pktio_t _pktio_iface;

public:
	odp_sink_pktio(ppp_graph *, const char *_name);
	~odp_sink_pktio();

	void set_pktio_iface(odp_pktio_t pktio_iface);

	virtual void input_pkt(ppp_packet *);
};

class odp_sink_drop : public odp_sink
{
public:
	odp_sink_drop(ppp_graph *, const char *_name);
	~odp_sink_drop();

	virtual void input_pkt(ppp_packet *);
};

#endif //_ODP_SINK_H
