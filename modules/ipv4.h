/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _IPV4_H
#define _IPV4_H

#include "../ppp/ppp_module.h"
#include "../ppp/ppp_edge.h"
#include "../ppp/ppp_route.h"

#ifdef SISU_ACCOUNTING
#define IP_NSTAGES 3

#define IP_STAGE_DESCS	 \
"IP Header Generation",  \
"IP Route Lookup",		 \
"IP Header Processing",

#define IP_FIELDS			\
IP_GENERATION,				\
IP_ROUTE_LOOKUP,			\
IP_STAGE_IP_PROCESSING,
#endif

// Bearer context - used for egress traffic
struct ipv4_bearer_context {
	uint32_t dst_ip;
	uint8_t dscp;
};

class ipv4 : public ppp_module
{
	ppp_rib rib;

	// Handler for ingress packet input
	void input_ingress_pkt(ppp_packet *pkt);

	// Handler for egress packet input
	void input_egress_pkt(ppp_packet *pkt);

public:
	uint32_t _local_ip;
	ppp_outputP discard; // Unwanted packets

	// Ingress direction
	ppp_inputP input_ingress;
	ppp_outputP output_ingress;

	// Egress direction
	ppp_inputP input_egress;
	ppp_outputP output_egress;

	// Constructor/destructor
	ipv4(ppp_graph *, const char *_name, uint32_t local_ip);
	~ipv4();

	void add_ppp_route(ppp_route *route);

	// Call apply function for outputs
	void traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *),
			      void *);
};

#endif //_IPV4_H
