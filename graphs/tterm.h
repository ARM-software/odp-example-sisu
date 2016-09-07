/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _TTERM_H
#define _TTERM_H

#include <stdio.h>
#include "../ppp/odp_sink.h"
#include "../ppp/odp_src.h"
#include "../ppp/ppp_graph.h"
#include "odp.h"

class tterm : public ppp_graph
{
	odp_sink_drop *_sink;
	odp_src *_src;

public:
	tterm(const char *name);
	~tterm();

	void stop();
	void start_flow(odp_queue_t in);
	void stop_flow(odp_queue_t in);

	queue_context *create_context(odp_queue_t queue);
	void destroy_context(queue_context *ctx);
};
#endif //_TTERM_H
