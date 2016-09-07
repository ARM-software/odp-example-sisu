/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#define __STDC_FORMAT_MACROS
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#include "../instr/debug.h"
#include "../instr/accounting.h"
#include "globals.h"
#include "../graphs/sisu.h"

queue_context::queue_context(ppp_module *mod, ppp_framing frm) :
							 framing(frm), output_pkt("output_pkt", mod) {}

queue_context::~queue_context() {}

void odp_src::stop()
{
	_stop = true;
}

void odp_src::traverse_outputs(void (*apply)(void *h, ppp_module *f, ppp_output *p), void *handle)
{
	apply(handle, this, &discard);
}

void odp_src::register_context(odp_queue_t queue, queue_context *ctx)
{
	// Ensure queue does not already have a context and thus is in use
	if (odp_queue_context(queue) != NULL)
	{
		odp_queue_to_u64(queue);
		exit(-1);
	}

	// Associate the context with the queue
	odp_queue_context_set(queue, ctx, sizeof(*ctx));
}

queue_context *odp_src::queue_context_get(odp_queue_t queue)
{
	queue_context *ctx = static_cast<queue_context *>
			(odp_queue_context(queue));

	if (unlikely(ctx == NULL))
		perror("odp_queue_get_context"), exit(-1);

	// Prefetch initial cache lines
	prefetch_r(ctx);
	prefetch_r((char*)ctx + ODP_CACHE_LINE_SIZE);
	return ctx;
}

ppp_outputP *odp_src::output_pkt(odp_queue_t queue)
{
	queue_context *ctx = queue_context_get(queue);

	return &ctx->output_pkt;
}

void odp_src::odp_src_handle_packet(odp_event_t ev, odp_queue_t queue)
{
	// Find context matching source queue
	queue_context *ctx = queue_context_get(queue);

	// Convert ODP packet handle to PPP packet object
	odp_packet_t pkth = odp_packet_from_event(ev);
	ppp_packet *pkt = static_cast<ppp_packet *>(odp_packet_head(pkth));

	// Initialize PPP packet metadata
	pkt->init(pkth, queue);
	pkt->ifindex_set(0); //FIXME
	pkt->parserflags_set(ctx->framing);

	if (ctx->framing == PPP_FRAMING_NONE) {
		pkt->hdrsize_set(sizeof(struct ipv4hdr));
		pkt->protocol_set(ntohs(PPP_FRAMETYPE_IPV4));
	} else if (ctx->framing == PPP_FRAMING_ETHERNET) {
		const ethhdr *eth = static_cast<const ethhdr *>(pkt->data_ptr());
		pkt->hdrsize_set(sizeof(struct ethhdr));
		pkt->protocol_set(ntohs(eth->frametype));
	}

#ifdef ENDTOEND
	if(! pkt->is_counting() ){
	    ACCOUNTING_BEGIN_PKT(pkt);
	}
#else
	ACCOUNTING_BEGIN_PKT(pkt);
#endif

	ACCOUNTING_END(ODP_SRC_STAGE_PREPARE_PACKET);
	// Pass packet on output
	ctx->output_pkt.enter(pkt);
}

void odp_src::odp_src_handle_timeout(odp_event_t ev)
{
	odp_timeout_t tmo = odp_timeout_from_event(ev);

	// Convert user pointer to input descriptor
	odp_src_input *inp = static_cast<odp_src_input *>(odp_timeout_user_ptr(tmo));

	// Pass event directly to input module
	inp->enter(ev);
}

void odp_src::odp_src_handle_crycompl(odp_event_t ev)
{
	odp_crypto_compl_t cry = odp_crypto_compl_from_event(ev);

	// Obtain the result data
	odp_crypto_op_result_t result;
	odp_crypto_compl_result(cry, &result);

	// Convert context pointer to input descriptor
	odp_src_input *inp = static_cast<odp_src_input *>(result.ctx);

	ACCOUNTING_END(ODP_SRC_STAGE_PREPARE_CRYPTO);
	// Pass event directly to input module
	inp->enter(ev);
}

void odp_src::sd_handler(int sd, int poll_events)
{
	uint32_t prev_val = 0;

	while (1) {
		if (_need_sync)
			((sisu *)graph)->data_plane_sync(&prev_val);

		odp_queue_t queue;
		ACCOUNTING_BEGIN();
		odp_event_t ev = odp_schedule(&queue, ODP_SCHED_NO_WAIT);

		if (unlikely(ev == ODP_EVENT_INVALID)) {
			if (_stop)
				break;
			continue;
		}
		ACCOUNTING_END(ODP_SRC_STAGE_SCHEDULE);

		ACCOUNTING_BEGIN();
		switch (odp_event_type(ev))
		{
			case ODP_EVENT_PACKET:
#ifdef SISU_DEBUG
			{
				odp_packet_t pkth = odp_packet_from_event(ev);
				ppp_packet *pkt = static_cast<ppp_packet *>(odp_packet_head(pkth));
				DEBUG_PKT_1("Scheduled from queue %lu", odp_queue_to_u64(queue));
			}
#endif
				odp_src_handle_packet(ev, queue);
				break;
			case ODP_EVENT_TIMEOUT:
				odp_src_handle_timeout(ev);
				return;
			case ODP_EVENT_CRYPTO_COMPL:
				odp_src_handle_crycompl(ev);
				break;
			default:
				fprintf(stderr, "Unrecognized event type %d\n",
				odp_event_type(ev));
				abort();
			/* UNREACHABLE */
		}
	}

	unregister_sd(sd);
}

odp_src::odp_src(ppp_graph *_graph, const char *_name, bool need_sync) :
				 ppp_module(_graph, _name, "odp"),
				 _need_sync(need_sync),
				 discard("discard", this)
{
	// Open a dummy file descriptor so that we can register to be called
	sd = open("/dev/null", O_RDONLY);
	if (sd == -1)
		perror("open"), abort();
	register_sd(sd, POLLIN);
	_stop = false;

	odp_queue_param_t qparam;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = odp_schedule_group_lookup(graph->name);
	FATAL_ERROR_COND(qparam.sched.group == ODP_SCHED_GROUP_INVALID, "odp_schedule_group_lookup");

	qparam.context = NULL;
}

odp_src::~odp_src()
{
	// Destroy queue used for endtimer
	close(sd);
}
