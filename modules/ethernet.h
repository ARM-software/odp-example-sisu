/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _ETHERNET_H
#define _ETHERNET_H

#include "../ppp/ppp_module.h"
#include "../ppp/ppp_edge.h"

#ifdef SISU_ACCOUNTING
#define ETH_NSTAGES 2

#define ETH_STAGE_DESCS			\
"Ethernet Header Generation",	\
"Ethernet Header Processing",

#define ETH_FIELDS			\
ETH_STAGE_ETH_GENERATION,	\
ETH_STAGE_ETH_PROCESSING,
#endif

#define ETH_ADDR_SIZE 6

// 8021q header
struct hdr8021q {
	uint8_t dstaddr[ETH_ADDR_SIZE];
	uint8_t srcaddr[ETH_ADDR_SIZE];
	uint16_t tpid;
	union {
		struct {
			uint16_t pcp : 3;
			uint16_t cfi : 1;
			uint16_t vid : 12;
		} tci;
		uint16_t tci_int;
	};
	uint16_t frametype;
};

// Bearer context - used for egress traffic
struct ethernet_bearer_context {
	uint8_t pcp;
};

class ethernet : public ppp_module
{
	// Handler for ingress packet input
	void input_ingress_pkt(ppp_packet *pkt);

	// Handler for egress packet input
	void input_egress_pkt(ppp_packet *pkt);

public:
	const uint8_t *_local_mac;
	ppp_outputP discard; // Unwanted packets

	// Ingress direction
	ppp_inputP input_ingress;
	ppp_outputP output_ingress;

	// Egress direction
	ppp_inputP input_egress;
	ppp_outputP output_egress;

	// Constructor/destructor
	ethernet(ppp_graph *, const char *_name, const uint8_t *_local_mac);
	~ethernet();

	// Call apply function for outputs
	void traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *),
			      void *);
};

#endif //_ETHERNET_H
