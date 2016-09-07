/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include "ppp_packet.h"
#include "odp_sink.h"

#include "../instr/accounting.h"
#include "../instr/debug.h"

void odp_sink_rr::input_pkt(ppp_packet *pkt)
{
ACCOUNTING_BEGIN();
	odp_queue_t queue;

	odp_rwlock_read_lock(&rwlock);
	if (_queue_it == _queue_list.end())
		_queue_it = _queue_list.begin();
	queue = *_queue_it;

	assert(queue != ODP_QUEUE_INVALID);
	_queue_it++;
	odp_rwlock_read_unlock(&rwlock);

	uint32_t pktlen = pkt->length();

	if (likely(queue != ODP_QUEUE_INVALID)) {
		stats.enq.pkts.add(1);
		stats.enq.bytes.add(pktlen);
		DEBUG_PKT_1("Sent to queue %lu", odp_queue_to_u64(queue));
		pkt->enqueue(queue);
ACCOUNTING_END(ODP_SINK_RR_SENT);
	} else {
ACCOUNTING_BEGIN();
		stats.free.pkts.add(1);
		stats.free.bytes.add(pktlen);
		DEBUG_PKT("Dropped");
		pkt->free();
ACCOUNTING_END(ODP_SINK_PACKET_FREED);
	}
}

void odp_sink_fixed::input_pkt(ppp_packet *pkt)
{
#ifndef ENDTOEND
    ACCOUNTING_END_PKT(ODP_SINK_WHOLE_EGRESS, pkt);
#endif
ACCOUNTING_BEGIN();
	odp_queue_t queue;
	queue = _fixed_queue;

	uint32_t pktlen = pkt->length();

	if (likely(queue != ODP_QUEUE_INVALID)) {
		stats.enq.pkts.add(1);
		stats.enq.bytes.add(pktlen);
		DEBUG_PKT_1("Sent to queue %lu", odp_queue_to_u64(queue));
		pkt->enqueue(queue);
ACCOUNTING_END(ODP_SINK_FIXED_SENT);
	} else {
ACCOUNTING_BEGIN();
		stats.free.pkts.add(1);
		stats.free.bytes.add(pktlen);
		DEBUG_PKT("Dropped");
		pkt->free();
ACCOUNTING_END(ODP_SINK_PACKET_FREED);
	}
}

void odp_sink_pktio::input_pkt(ppp_packet *pkt)
{
	int status;
	uint32_t pktlen = pkt->length();
	odp_pktout_queue_t queue;

	odp_pktout_queue(_pktio_iface, &queue, 1);
	status = odp_pktout_send(queue, &pkt->_pkth, 1);

	if (likely(status == 1)) {
		stats.enq.pkts.add(1);
		stats.enq.bytes.add(pktlen);
		DEBUG_PKT_1("Sent to pktio %lu", odp_pktio_to_u64(_pktio_iface));
	} else {
		stats.free.pkts.add(1);
		stats.free.bytes.add(pktlen);
		DEBUG_PKT("Dropped");
	}
}

void odp_sink_drop::input_pkt(ppp_packet *pkt)
{
ACCOUNTING_BEGIN();
	stats.free.pkts.add(1);
	DEBUG_PKT("Freed");
	pkt->free();
ACCOUNTING_END(ODP_SINK_PACKET_FREED);
}

void odp_sink::input_pkt(ppp_packet *pkt)
{
#ifndef ENDTOEND
ACCOUNTING_END_PKT(ODP_SINK_WHOLE_INGRESS, pkt);
#else
ACCOUNTING_END_PKT(ODP_SINK_WHOLE_SYSTEM, pkt);
#endif
ACCOUNTING_BEGIN();
	odp_queue_t queue;

	queue = pkt->queue();

	uint32_t pktlen = pkt->length();

	if (likely(queue != ODP_QUEUE_INVALID)) {
		stats.enq.pkts.add(1);
		stats.enq.bytes.add(pktlen);
		DEBUG_PKT_1("Sent to queue %lu", odp_queue_to_u64(queue));
		pkt->enqueue(queue);
ACCOUNTING_END(ODP_SINK_PACKET_SENT);
	} else {
ACCOUNTING_BEGIN();
		stats.free.pkts.add(1);
		stats.free.bytes.add(pktlen);
		DEBUG_PKT("Dropped");
		pkt->free();
ACCOUNTING_END(ODP_SINK_PACKET_FREED);
	}
}

void odp_sink_fixed::set_fixed_queue(odp_queue_t queue)
{
	_fixed_queue = queue;
}

void odp_sink_pktio::set_pktio_iface(odp_pktio_t pktio_iface)
{
	_pktio_iface = pktio_iface;
}

void odp_sink_rr::register_queue(odp_queue_t queue)
{
	odp_rwlock_write_lock(&rwlock);
	_queue_list.push_back(queue);
	odp_rwlock_write_unlock(&rwlock);
}

void odp_sink_rr::deregister_queue(odp_queue_t queue)
{
	odp_rwlock_write_lock(&rwlock);
	if (*_queue_it == queue)
		_queue_it++;

	std::list<odp_queue_t>::iterator it;
	for (it = _queue_list.begin(); it != _queue_list.end(); it++) {
		if (*it == queue) {
			_queue_list.erase(it);
			break;
		}
	}
	odp_rwlock_write_unlock(&rwlock);
}

void odp_sink::traverse_outputs(void (*apply)(void *h, ppp_module *f, ppp_output *p), void *handle) {}

odp_sink_rr::odp_sink_rr(ppp_graph *_graph, const char *_name) :
			odp_sink(_graph, _name)
{
	_queue_it = _queue_list.begin();
	odp_rwlock_init(&rwlock);
}

odp_sink_rr::~odp_sink_rr() {}

odp_sink_fixed::odp_sink_fixed(ppp_graph *_graph, const char *_name) :
			odp_sink(_graph, _name) {}

odp_sink_fixed::~odp_sink_fixed() {}

odp_sink_pktio::odp_sink_pktio(ppp_graph *_graph, const char *_name) :
			odp_sink(_graph, _name) {}

odp_sink_pktio::~odp_sink_pktio() {}

odp_sink_drop::odp_sink_drop(ppp_graph *_graph, const char *_name) :
			odp_sink(_graph, _name) {}

odp_sink_drop::~odp_sink_drop() {}

odp_sink::odp_sink(ppp_graph *_graph, const char *_name) :
				   ppp_module(_graph, _name, "sink"),
				   input("input", this, (ppp_edgeP_f)&odp_sink::input_pkt) {}

odp_sink::~odp_sink() {}
