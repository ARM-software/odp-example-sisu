/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _ODP_SRC_H
#define _ODP_SRC_H

#include <list>

#include "ppp_packet.h"
#include "ppp_module.h"
#include "ppp_edge.h"

#ifdef SISU_ACCOUNTING
#define ODP_SRC_NSTAGES 4

#define ODP_SRC_DESCS	 \
"ODP Source Schedule",	 \
"Prepare packet",	 \
"Prepare cryto event",	 \
"ODP Source Total",

#define ODP_SRC_FIELDS		  \
ODP_SRC_STAGE_SCHEDULE,		  \
ODP_SRC_STAGE_PREPARE_PACKET, \
ODP_SRC_STAGE_PREPARE_CRYPTO, \
ODP_SRC_STAGE_TOTAL,
#endif

class ppp_timer;
class odp_src;

// odp_callback_f - connection with event as a parameter
typedef void (ppp_module::*odp_callback_f)(odp_event_t evt, void *ctx);

// All event inputs must derive from odp_src_input
class odp_src_input
{
public:
	ppp_module *module;
	odp_callback_f function;
	void *context;
	inline void enter(odp_event_t evt)
	{
		((module)->*(function))(evt, context);
	}
};

// The context stores where packets should go to
class queue_context
{
	enum ppp_framing framing;
	ppp_outputP output_pkt;

public:
	queue_context(ppp_module *, ppp_framing);
	~queue_context();

	friend class odp_src;
};

class odp_src : public ppp_module
{
	int sd;
	bool _need_sync;

	// These are used for terminating the thread
protected:
	volatile bool _stop;

public:
	ppp_outputP discard;

	odp_src(ppp_graph *, const char *_name, bool need_sync = false);
	~odp_src();

	virtual void traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *);
	void sd_handler(int sd, int poll_handler);

	void register_context(odp_queue_t, queue_context *);
	queue_context *queue_context_get(odp_queue_t);
	ppp_outputP *output_pkt(odp_queue_t);

	// Event handlers
	void odp_src_handle_packet(odp_event_t, odp_queue_t);
	void odp_src_handle_timeout(odp_event_t);
	void odp_src_handle_crycompl(odp_event_t);

	// Timeout handler
	void handle_tmo(odp_event_t evt, void *ctx);

	// Calling stop() will create a termination timer
	void stop();
};

#endif //_ODP_SRC_H
