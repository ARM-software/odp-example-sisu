/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include "gtpu.h"

#include <string>

#include "../instr/accounting.h"
#include "../instr/debug.h"
#include "../ppp/ppp_packet.h"

#define GTPU_FLAGS 0x30FF
#define GTPU_PORT 2152

// Handler for egress packets
void gtpu::input_egress_pkt(ppp_packet *pkt)
{
	ACCOUNTING_BEGIN();
	uint32_t pkt_length = pkt->length();

	gtpu_bearer_context *ctx = static_cast<gtpu_bearer_context *>(pkt->context());

	// GTP-U processing
	struct gtpuhdr *gtpu_hdr = static_cast<struct gtpuhdr *>(pkt->grow_head(sizeof(struct gtpuhdr)));

	gtpu_hdr->flags_int = htons(GTPU_FLAGS);
	gtpu_hdr->length = htons(pkt_length);
	gtpu_hdr->teid = htonl(ctx->teid);
	DEBUG_PKT("UDP header generated");

	// UDP processing
	struct udphdr *udp_hdr = static_cast<struct udphdr *>(pkt->grow_head(sizeof(struct udphdr)));

	udp_hdr->src_port = udp_hdr->dst_port = htons(GTPU_PORT);
	udp_hdr->length = htons(pkt_length + sizeof(struct udphdr) + sizeof(struct gtpuhdr));
	udp_hdr->chksum = 0; // UDP checksum is optional. It might be calculated at a later stage.

	pkt->context_skip(sizeof(struct gtpu_bearer_context));

	ACCOUNTING_END(GTP_UDP_GENERATION);

	DEBUG_PKT("GTP header generated");

	output_egress.enter(pkt);
}

// Handler for ingress packets
void gtpu::input_ingress_pkt(ppp_packet *pkt)
{
	ACCOUNTING_BEGIN();
	// UDP processing
	void *p = pkt->data_ptr();
	struct udphdr *udp_hdr = static_cast<struct udphdr *>(p);

	if (ntohs(udp_hdr->dst_port) != GTPU_PORT) {
		DEBUG_PKT("Incorrect GTP port");
		discard.enter(pkt);
		return;
	}

	pkt->trim_head(sizeof(struct udphdr));
	DEBUG_PKT("UDP processing successful");

	// GTP-U processing
	p = pkt->data_ptr();
	struct gtpuhdr *gtpu_hdr = static_cast<struct gtpuhdr *>(p);

	if (ntohs(gtpu_hdr->flags_int) != GTPU_FLAGS) {
		DEBUG_PKT("Incorrect GTP flags");
		discard.enter(pkt);
		return;
	}

	pkt->trim_head(sizeof(struct gtpuhdr));
	ACCOUNTING_END(GTP_UDP_PROCESSING);

	ACCOUNTING_BEGIN();
	uint16_t teid_high = ntohl(gtpu_hdr->teid) >> 16;
	uint16_t teid_low = ntohl(gtpu_hdr->teid) & 0x0000FFFF;

	struct queue_entry *entry = &q_table.queue_entries[teid_low];
	if ((entry->counter != teid_high) || (unlikely(entry->queue == ODP_QUEUE_INVALID))) {
		DEBUG_PKT("Local TEID not found");
		discard.enter(pkt);
		return;
	}

	pkt->trim_head(sizeof(struct gtpuhdr));
	pkt->queue_set(entry->queue);
	ACCOUNTING_END(GTP_TEID_LOOKUP);
	DEBUG_PKT("GTP processing successful");

	output_ingress.enter(pkt);
}

uint32_t gtpu::queue_table_add(odp_queue_t queue)
{
	assert(queue != ODP_QUEUE_INVALID);
	assert(q_table.stack_idx != 0);

	uint16_t teid_low = q_table.teids_stack[--(q_table.stack_idx)];

	assert(q_table.queue_entries[teid_low].queue == ODP_QUEUE_INVALID);

	q_table.queue_entries[teid_low].queue = queue;
	uint16_t teid_high = q_table.queue_entries[teid_low].counter;

	return (uint32_t)(teid_high << 16) | (uint32_t)(teid_low);
}

void gtpu::queue_table_del(uint32_t teid)
{
	uint16_t teid_low = teid & 0x0000FFFF;

	assert(q_table.queue_entries[teid_low].queue != ODP_QUEUE_INVALID);

	q_table.queue_entries[teid_low].queue = ODP_QUEUE_INVALID;
	q_table.queue_entries[teid_low].counter++;

	q_table.teids_stack[(q_table.stack_idx)++] = teid_low;
}

gtpu::gtpu(ppp_graph *_g, const char *_n) : ppp_module(_g, _n, "tunnel"),
		   discard("discard", this),
		   input_ingress("input_ingress", this, (ppp_edgeP_f)&gtpu::input_ingress_pkt, 0),
		   output_ingress("output_ingress", this, 0),
		   input_egress("input_egress", this, (ppp_edgeP_f)&gtpu::input_egress_pkt, 0),
		   output_egress("output_egress", this, 0)
{
	// Initialize queue table used in the ingress path
	q_table.stack_idx = 0;
	for (int i = 0; i < N_TEIDS; i++) {
		q_table.teids_stack[q_table.stack_idx++] = i;
		q_table.queue_entries[i].queue = ODP_QUEUE_INVALID;
		q_table.queue_entries[i].counter = 0;
	}
}

gtpu::~gtpu() {}

void gtpu::traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *handle)
{
	apply(handle, this, &output_ingress);
	apply(handle, this, &output_egress);
	apply(handle, this, &discard);
}
