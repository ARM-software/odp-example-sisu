/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _ACCOUNTING_H
#define _ACCOUNTING_H

#include <stdint.h>

#include "../graphs/tgen.h"
#include "../modules/gtpu.h"
#include "../modules/ipv4.h"
#include "../modules/ethernet.h"
#include "../modules/ipsec.h"
#include "../ppp/odp_src.h"
#include "../ppp/odp_sink.h"
#include "../ppp/ppp_packet.h"

#ifdef SISU_ACCOUNTING
#include "../ppp/timestamp.h"
#include "arch.h"
#include "pmu.h"

#define STACK_LVL_MAX 5
#define MAX_N_CORES 16
#define N_STAGES ((GTP_NSTAGES) + \
		  (IP_NSTAGES) + \
		  (IPSEC_NSTAGES) + \
		  (ETH_NSTAGES) + \
		  (ODP_SRC_NSTAGES) + \
		  (ODP_SINK_NSTAGES) + \
		  (TGEN_NSTAGES))

struct stage_data {
	uint64_t cycles;
	uint64_t l1_misses;
	uint64_t l2_misses;
	uint64_t instr;
	uint64_t packets;
} ODP_ALIGNED_CACHE;

enum proc_stage_index {
	TGEN_FIELDS // These are actually macros provided by modules
	ODP_SRC_FIELDS
	GTP_FIELDS
	IP_FIELDS
	IPSEC_FIELDS
	ETH_FIELDS
	ODP_SINK_FIELDS
};

extern int __thread core_id;
extern bool core_in_use[MAX_N_CORES];
extern const char *thread_desc[MAX_N_CORES];
extern const char *stage_desc[];
extern struct stage_data stage[MAX_N_CORES][N_STAGES];
extern struct stage_data __thread data_buf;

#define ACCOUNTING_BEGIN() do {	\
		data_buf.l1_misses = pmu_get_event_counter(L1_CACHE_REFILL);\
		data_buf.l2_misses = pmu_get_event_counter(L2_CACHE_REFILL);\
		data_buf.instr = pmu_get_event_counter(INSTR_RETIRED);	    \
		data_buf.cycles = pmu_get_cycle_counter();		    \
	} while (0)

#define ACCOUNTING_END(st) do {	\
		stage[core_id][(st)].cycles += pmu_get_cycle_counter() - data_buf.cycles; \
		stage[core_id][(st)].instr += (uint64_t)((uint32_t)pmu_get_event_counter(INSTR_RETIRED) - (uint32_t)data_buf.instr); \
		stage[core_id][(st)].l1_misses += (uint64_t)((uint32_t)pmu_get_event_counter(L1_CACHE_REFILL) - (uint32_t)data_buf.l1_misses); \
		stage[core_id][(st)].l2_misses += (uint64_t)((uint32_t)pmu_get_event_counter(L2_CACHE_REFILL) - (uint32_t)data_buf.l2_misses); \
		stage[core_id][(st)].packets++; \
	} while (0)

#define ACCOUNTING_BEGIN_PKT(pkt) pkt->cycles_begin()

#define ACCOUNTING_END_PKT(st, pkt) do { \
		pkt->cycles_end(); \
		stage[core_id][(st)].cycles += pkt->cycles(); \
		stage[core_id][(st)].packets++; \
	} while (0)

#else
#define ACCOUNTING_BEGIN()
#define ACCOUNTING_END(stage)
#define ACCOUNTING_BEGIN_PKT(pkt)
#define ACCOUNTING_END_PKT(st, pkt)
#endif

void print_report();

#endif
