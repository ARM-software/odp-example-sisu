/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _GTPU_H
#define _GTPU_H

#include "../ppp/ppp_module.h"
#include "../ppp/ppp_edge.h"

#ifdef SISU_ACCOUNTING
#define GTP_NSTAGES 3

#define GTP_STAGE_DESCS	 \
"GTP & UDP Header Generation", \
"GTP & UDP Header Processing", \
"GTP TEID lookup",

#define GTP_FIELDS			\
GTP_UDP_GENERATION,         \
GTP_UDP_PROCESSING,			\
GTP_TEID_LOOKUP,
#endif

#define N_TEIDS (1 << 16)

// GTP-U header
struct gtpuhdr {
	union {
		struct {
			uint8_t version : 3;
			uint8_t pt : 1;
			uint8_t sp : 1;
			uint8_t e : 1;
			uint8_t s : 1;
			uint8_t pn : 1;
			uint8_t type;
		} flags;
		uint16_t flags_int;
	};
	uint16_t length;
	uint32_t teid;
};

// Bearer context - used for egress traffic
struct gtpu_bearer_context {
	uint32_t teid;
	uint32_t dst_ip;
};

// Queue ID table - used for ingress traffic
struct queue_entry {
	odp_queue_t queue;
	uint16_t counter;
};

struct queue_id_table {
	struct queue_entry queue_entries[N_TEIDS];
	uint16_t teids_stack[N_TEIDS];
	uint32_t stack_idx;
};

class gtpu : public ppp_module
{
	struct queue_id_table q_table;

	// Handler for ingress packet input
	void input_ingress_pkt(ppp_packet *pkt);

	// Handler for egress packet input
	void input_egress_pkt(ppp_packet *pkt);

public:
	ppp_outputP discard; // Unwanted packets

	// Ingress direction
	ppp_inputP input_ingress;
	ppp_outputP output_ingress;

	// Egress direction
	ppp_inputP input_egress;
	ppp_outputP output_egress;

	// Constructor/destructor
	gtpu(ppp_graph *, const char *_name);
	~gtpu();

	// Functions to modify queue table
	uint32_t queue_table_add(odp_queue_t queue);
	void queue_table_del(uint32_t teid);

	// Call apply function for outputs
	void traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *),
			      void *);
};

#endif //_GTPU_H
