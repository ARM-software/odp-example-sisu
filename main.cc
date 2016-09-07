/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <unistd.h>
#include <getopt.h>
#include <time.h>

#include "ppp/ppp_graph.h"
#include "ppp/ppp_pktpool.h"
#include "ppp/ppp_timer.h"

#include "odp.h"
#include "odp/helper/linux.h"

#include "instr/accounting.h"
#include "instr/debug.h"
#include "agent/cpagent.h"
#include "graphs/sisu.h"
#include "graphs/tgen.h"
#include "graphs/tterm.h"

#define MAX_N_CORES	16
#define NUMTMOS (1 << 16)
#define TIMER_RES_NS 2000000
#define N_FLOWS (1 << 16)

#define POOL_NUMPKTS 30
#define POOL_HEADROOM 64
#define POOL_MAXSIZE 0x500
#define MAX_N_THREADS (1 << 8)
#define IP_ADDR 0x01020304

#define NEW_CONN_MEAN 100
#define CONN_LIFETIME_AVG 5

#define MAX_LONG_OPTS 10

const uint8_t MAC[] = {0x00, 0x04, 0x9f, 0x04, 0x03, 0xe0};

// User parameters
bool debug_pcap = false;
char *iface = (char *)"lo";
char *oface = (char *)"lo";
odp_cpumask_t tgen_cpumask;
odp_cpumask_t tterm_cpumask;
odp_cpumask_t pp_cpumask;

// ODP handlers
odp_instance_t odp_instance;
ppp_timer_pool *timer_pool;

// Thread table
odph_linux_pthread_t thread_tbl[MAX_N_THREADS];
uint8_t thread_idx;

static void parse_cores(odp_cpumask_t *cpumask, char *str)
{
	char *next;
	char s[2] = ",";

	odp_cpumask_zero(cpumask);

	next = strtok(str, s);
	while (next != NULL) {
		odp_cpumask_set(cpumask, atoi(next));
		next = strtok(NULL, s);
	}
}

static void
parse_params(int argc, char *argv[])
{
	struct option long_opts[MAX_LONG_OPTS];
	int c, n_opts = 0;

	/* Configure the framework's options */
	long_opts[n_opts++] = (struct option){"pcap", no_argument, 0, 'c'};
	long_opts[n_opts++] = (struct option){"only-debug-discarded", no_argument, 0, 'd'};
	long_opts[n_opts++] = (struct option){"tgen", required_argument, 0, 'g'};
	long_opts[n_opts++] = (struct option){"tterm", required_argument, 0, 't'};
	long_opts[n_opts++] = (struct option){"pp", required_argument, 0, 'p'};
	long_opts[n_opts++] = (struct option){"iface", required_argument, 0, 'z'};
	long_opts[n_opts++] = (struct option){"oface", required_argument, 0, 'y'};
	long_opts[n_opts++] = (struct option){0, 0, 0, 0};

	int long_index = 0;
	while ((c = getopt_long(argc, argv, "cdgtpzy", long_opts, &long_index)) != -1) {
		switch (c) {
		case 'c':
			debug_pcap = true;
			break;
		case 'g':
			parse_cores(&tgen_cpumask, optarg);
			break;
		case 't':
			parse_cores(&tterm_cpumask, optarg);
			break;
		case 'p':
			parse_cores(&pp_cpumask, optarg);
			break;
		case 'z':
			iface = optarg;
			break;
		case 'y':
			oface = optarg;
			break;
#ifdef SISU_DEBUG
		case 'd':
			only_discarded = true;
			break;
#endif
		default:
			goto error;
		}
	}

	return;

error:
	abort();
}

void *do_graph_run(void *arg)
{
	ppp_graph *g = (ppp_graph *)arg;

#ifdef SISU_ACCOUNTING
	pmu_init();
	core_id = odp_cpu_id();
	thread_desc[core_id] = g->name;
	core_in_use[core_id] = true;
#endif

	g->execute();

	return NULL;
}

void graph_run(ppp_graph *g, odp_cpumask_t cpumask)
{
	char mask_str[10];
	odph_linux_thr_params_t thr_params;

	odp_cpumask_to_str(&cpumask, mask_str, sizeof(mask_str));

	thr_params.start = do_graph_run;
	thr_params.arg = g;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = odp_instance;

	printf("Executing graph %s with coremask %s\n", g->name, mask_str);
	odph_linux_pthread_create(&thread_tbl[thread_idx++], &cpumask, &thr_params);
}

int main(int argc, char *argv[])
{
	// Parse user parameters
	parse_params(argc, argv);

	// Initialize seed
	srand(time(NULL));

	// Initialise ODP
	if (odp_init_global(&odp_instance, NULL, NULL))
		perror("odp_init_global"), exit(EXIT_FAILURE);

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL))
		perror("odp_init_local"), exit(EXIT_FAILURE);

	// Create the default packet pool
	ppp_pktpool *pktpool = new ppp_pktpool("main1", POOL_NUMPKTS, POOL_HEADROOM, POOL_MAXSIZE);

	// Create timer pool
	timer_pool = new ppp_timer_pool("global_timers", TIMER_RES_NS, N_FLOWS);

	// Create traffic generators
	tgen *tgen_instance = new tgen("TGEN", pktpool);

	// Create traffic terminators
	tterm *tterm_instance = new tterm("TTERM");

	// Create SISU instances
	sisu *sisu_instance = new sisu("SISU", IP_ADDR, MAC, debug_pcap);

	// Create Control Plane Agent instance
	cpagent *agent = new cpagent(tgen_instance, sisu_instance, tterm_instance, iface, oface);

	// Enter configure mode before starting to process traffic
	agent->enter_configure_mode();

	// Execute graphs on separate threads
	if (odp_cpumask_count(&pp_cpumask)) {
		graph_run(sisu_instance, pp_cpumask);
	}

	if (odp_cpumask_count(&tgen_cpumask)) {
		graph_run(tgen_instance, tgen_cpumask);
	}

	if (odp_cpumask_count(&tterm_cpumask)) {
		graph_run(tterm_instance, tterm_cpumask);
	}

	// Enter configure mode again, so that the control plane application can stop it remotely
	agent->enter_configure_mode();

	// Wait for all the threads to finish
	odph_linux_pthread_join(thread_tbl, thread_idx);

	// List network interface configurations and statistics
	printf("\n/Tgen 1/\n");
	tgen_instance->list_if();
	printf("\n/Packet Processing/\n");
	sisu_instance->list_if();

	// Performance report
	print_report();

	// Delete resources
	int rc;

	delete agent;
	delete tgen_instance;
	delete tterm_instance;
	delete sisu_instance;
	delete timer_pool;
	delete pktpool;

	rc = odp_term_local();

	if (rc < 0)
		perror("odp_term_local"), abort();

	if (rc == 0) {
		rc = odp_term_global(odp_instance);

		if (rc < 0)
			perror("odp_term_global"), abort();
	}

	return 0;
}
