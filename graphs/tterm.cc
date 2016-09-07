/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../ppp/ppp_packet.h"
#include "../ppp/ppp_graph.h"

#include "tterm.h"

void tterm::stop()
{
	_src->stop();
}

void tterm::start_flow(odp_queue_t in)
{
	_src->output_pkt(in)->attach(&(_sink->input));
}

void tterm::stop_flow(odp_queue_t in)
{
	_src->output_pkt(in)->attach(NULL);
}

queue_context *tterm::create_context(odp_queue_t queue)
{
	queue_context *ctx = new queue_context(_src, PPP_FRAMING_ETHERNET);
	_src->register_context(queue, ctx);

	return ctx;
}

void tterm::destroy_context(queue_context *ctx)
{
	delete ctx;
}

tterm::tterm(const char *name) : ppp_graph(name, 5)
{
	_src = new odp_src(this, "src");
	_sink = new odp_sink_drop(this, "sink");
}

tterm::~tterm()
{
	delete _src;
	delete _sink;
}