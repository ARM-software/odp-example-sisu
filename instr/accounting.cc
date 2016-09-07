/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include "accounting.h"

#ifdef SISU_ACCOUNTING
int __thread core_id;
struct stage_data __thread data_buf;

const char *stage_desc[] = {
	TGEN_STAGE_DESCS
	ODP_SRC_DESCS
	GTP_STAGE_DESCS
	IP_STAGE_DESCS
	IPSEC_STAGE_DESCS
	ETH_STAGE_DESCS
	ODP_SINK_STAGE_DESCS
};

bool core_in_use[MAX_N_CORES];
const char *thread_desc[MAX_N_CORES];
struct stage_data stage[MAX_N_CORES][N_STAGES];
#endif

void print_report()
{
#ifdef SISU_ACCOUNTING
	uint64_t total = 0;

	printf("\n\n*** Performance report ***\n");
	for (int j = 0; j < MAX_N_CORES; j++) {
		if (!core_in_use[j])
			continue;
		printf("Core %d - %s\n", j, thread_desc[j]);
		for (int i = 0; i < N_STAGES; i++) {
			if (stage[j][i].packets == 0)
				continue;
			total += stage[j][i].cycles;
			if (stage[j][i].packets > 0)
				printf("%s: %lu / %lu l1 / %lu l2 / %lu instr / %lu packets\n",
						stage_desc[i], stage[j][i].cycles / stage[j][i].packets,
						stage[j][i].l1_misses / stage[j][i].packets,
						stage[j][i].l2_misses / stage[j][i].packets,
						stage[j][i].instr / stage[j][i].packets,
						stage[j][i].packets);
		}
		printf("\n");
	}
#endif
}
