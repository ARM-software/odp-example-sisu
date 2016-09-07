/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "../instr/debug.h"
#include "ppp_module.h"
#include "ppp_graph.h"
#include "ppp_pktpool.h"

void ppp_module::discard_pkt(ppp_packet *pkt)
{
    pkt->cycles_end();
#ifdef SISU_DEBUG
	pkt->log_set_discarded();
#endif
    pkt->free();
    num_discard_evt.add(1);
}

void ppp_module::discard_pkt2(ppp_packet *pkt, uint32_t arg)
{
    pkt->cycles_end();
    pkt->free();
    num_discard_evt.add(1);
}

void ppp_module::discard_evt(odp_event_t evt, void *ctx)
{
    (void)ctx;
    switch (odp_event_type(evt))
    {
	case ODP_EVENT_BUFFER:
	    odp_buffer_free(odp_buffer_from_event(evt));
	    break;
	case ODP_EVENT_PACKET:
	    odp_packet_free(odp_packet_from_event(evt));
	    break;
	case ODP_EVENT_TIMEOUT:
	    odp_timeout_free(odp_timeout_from_event(evt));
	    break;
	case ODP_EVENT_CRYPTO_COMPL:
	    odp_crypto_compl_free(odp_crypto_compl_from_event(evt));
	    break;
	default:
	    fprintf(stderr, "Unknown event type %d\n", odp_event_type(evt));
	    abort();
    }
    num_discard_evt.add(1);
}

ppp_module::ppp_module(ppp_graph *g, const char *n, const char *t) :
    graph(g),
    name(n),
    type(t),
    num_discard_evt(0)
{
    graph->insert_module(this);
}

ppp_module::~ppp_module()
{
    graph->remove_module(this);
}

void ppp_module::sd_handler(int sd, int poll_events)
{
    fprintf(stderr, "%s: default sd_handler called\n", name);
    abort();
}

void ppp_module::register_sd(int sd, int poll_events)
{
    graph->register_sd(this, sd, poll_events);
}

void ppp_module::unregister_sd(int sd)
{
    graph->unregister_sd(sd);
}

