/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include "ipv4.h"

#include "../instr/accounting.h"
#include "../instr/debug.h"
#include "../ppp/ppp_packet.h"

#define IPV4_VERS_HLEN 0x45
#define IPV4_DEF_TTL 64
#define IPV4_TOS 0x00

// Handler for egress packets
void ipv4::input_egress_pkt(ppp_packet *pkt)
{
	ACCOUNTING_BEGIN();
	uint32_t pkt_length = pkt->length();

	ipv4_bearer_context *ctx = static_cast<ipv4_bearer_context *>(pkt->context());

	// IPv4 processing
	struct ipv4hdr *ipv4_hdr = static_cast<struct ipv4hdr *>(pkt->grow_head(sizeof(struct ipv4hdr)));

	ipv4_hdr->vers_hlen = IPV4_VERS_HLEN;
	ipv4_hdr->tos = IPV4_TOS | (ctx->dscp << 2);
	ipv4_hdr->total_len = htons(pkt_length + sizeof(struct ipv4hdr));
	ipv4_hdr->id = 0; // TODO fragmentation not supported
	ipv4_hdr->fraginfo = 0; // TODO fragmentation not supported
	ipv4_hdr->ttl = IPV4_DEF_TTL;
	ipv4_hdr->ip_proto = PPP_IPPROTO_UDP;
	ipv4_hdr->src_addr = htonl(_local_ip);
	ipv4_hdr->dst_addr = htonl(ctx->dst_ip);
	ipv4_hdr->hchecksum = 0;
	ipv4_hdr->hchecksum = ipv4_hdr->checksum();

	// Calculate UDP checksum
	struct udphdr *udp_hdr = (struct udphdr *)((uint8_t *)(ipv4_hdr) + sizeof(struct ipv4hdr));
	udp_hdr->chksum = udp_hdr->checksum(udp_hdr->payload_ptr());

	pkt->context_skip(sizeof(struct ipv4_bearer_context));
	ACCOUNTING_END(IP_GENERATION);

	ACCOUNTING_BEGIN();
	// Lookup the route in the LPM table
	pkt->route_set(rib.find_lpm(ctx->dst_ip));
	ACCOUNTING_END(IP_ROUTE_LOOKUP);

	DEBUG_PKT("IP header generated");

	output_egress.enter(pkt);
}

void ipv4::add_ppp_route(ppp_route *route){
	rib.add_route(route);
}

// Handler for ingress packets
void ipv4::input_ingress_pkt(ppp_packet *pkt)
{
	ACCOUNTING_BEGIN();
	// IPv4 processing
	void *p = pkt->data_ptr();
	struct ipv4hdr *ipv4_hdr = static_cast<struct ipv4hdr *>(p);

	// Check UDP checksum
	struct udphdr *udp_hdr = (struct udphdr *)((uint8_t *)(ipv4_hdr) + sizeof(struct ipv4hdr));
	uint16_t checksum = udp_hdr->chksum;
	udp_hdr->chksum = 0;

	if ((ipv4_hdr->ip_proto != PPP_IPPROTO_UDP) ||
				(checksum != udp_hdr->checksum(udp_hdr->payload_ptr()))) {
		DEBUG_PKT("Incorrect UDP checksum");
		discard.enter(pkt);
		return;
	}

	checksum = ipv4_hdr->hchecksum;
	ipv4_hdr->hchecksum = 0;

	// TODO ignore fragmentation fields. Reassembly not supported
	if ((ipv4_hdr->vers_hlen != IPV4_VERS_HLEN) ||
				(ntohl(ipv4_hdr->dst_addr) != _local_ip) ||
				(checksum != ipv4_hdr->checksum())) {
		DEBUG_PKT("Incorrect IP header");
		discard.enter(pkt);
		return;
	}

	pkt->trim_head(sizeof(struct ipv4hdr));
	ACCOUNTING_END(IP_STAGE_IP_PROCESSING);
	DEBUG_PKT("IP processing successful");

	output_ingress.enter(pkt);
}

ipv4::ipv4(ppp_graph *_g, const char *_n, uint32_t local_ip) : ppp_module(_g, _n, "tunnel"),
		   _local_ip(local_ip), discard("discard", this),
		   input_ingress("input_ingress", this, (ppp_edgeP_f)&ipv4::input_ingress_pkt, 0),
		   output_ingress("output_ingress", this, 0),
		   input_egress("input_egress", this, (ppp_edgeP_f)&ipv4::input_egress_pkt, 0),
		   output_egress("output_egress", this, 0) {}

ipv4::~ipv4() {}

void ipv4::traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *handle)
{
	apply(handle, this, &output_ingress);
	apply(handle, this, &output_egress);
	apply(handle, this, &discard);
}
