/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include "ethernet.h"

#include "../instr/accounting.h"
#include "../instr/debug.h"
#include "../ppp/ppp_packet.h"
#include "../ppp/ppp_route.h"

#define ETH_TPID 0x8100
#define ETH_TCI 0x0000
#define ETH_TYPE 0x0800

// Handler for egress packets
void ethernet::input_egress_pkt(ppp_packet *pkt)
{
	ACCOUNTING_BEGIN();
	ethernet_bearer_context *ctx = static_cast<ethernet_bearer_context *>(pkt->context());

	// Ethernet processing
	struct hdr8021q *eth_hdr = static_cast<struct hdr8021q *>(pkt->grow_head(sizeof(struct hdr8021q)));

	ppp_route *route = pkt->route();
	memcpy(eth_hdr->dstaddr, route->macaddr, ETH_ADDR_SIZE);
	memcpy(eth_hdr->srcaddr, _local_mac, ETH_ADDR_SIZE);

	eth_hdr->tpid = htons(ETH_TPID);
	eth_hdr->tci_int = htons(ETH_TCI | (ctx->pcp << 13));
	eth_hdr->frametype = htons(ETH_TYPE);

	pkt->context_skip(sizeof(struct ethernet_bearer_context));
	ACCOUNTING_END(ETH_STAGE_ETH_GENERATION);

	DEBUG_PKT("Ethernet header generated");
	output_egress.enter(pkt);
}

// Handler for ingress packets
void ethernet::input_ingress_pkt(ppp_packet *pkt)
{
	ACCOUNTING_BEGIN();
	// Ethernet processing
	void *p = pkt->data_ptr();
	struct hdr8021q *eth_hdr = static_cast<struct hdr8021q *>(p);

	if ((memcmp(eth_hdr->dstaddr, _local_mac, ETH_ADDR_SIZE) != 0) ||
				(ntohs(eth_hdr->tpid) != ETH_TPID) ||
				(ntohs(eth_hdr->frametype) != ETH_TYPE)) {
		DEBUG_PKT("Incorrect ethernet header");
		discard.enter(pkt);
		return;
	}

	pkt->trim_head(sizeof(struct hdr8021q));
	ACCOUNTING_END(ETH_STAGE_ETH_PROCESSING);
	DEBUG_PKT("Ethernet processing successsful");

	output_ingress.enter(pkt);
}

ethernet::ethernet(ppp_graph *_g, const char *_n, const uint8_t *local_mac) : ppp_module(_g, _n, "tunnel"),
		   _local_mac(local_mac),
		   discard("discard", this),
		   input_ingress("input_ingress", this, (ppp_edgeP_f)&ethernet::input_ingress_pkt, 0),
		   output_ingress("output_ingress", this, 0),
		   input_egress("input_egress", this, (ppp_edgeP_f)&ethernet::input_egress_pkt, 0),
		   output_egress("output_egress", this, 0) {}

ethernet::~ethernet() {}

void ethernet::traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *handle)
{
	apply(handle, this, &output_ingress);
	apply(handle, this, &output_egress);
	apply(handle, this, &discard);
}
