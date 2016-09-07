/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _SISU_H
#define _SISU_H

#include <stdint.h>

#include "../ppp/odp_src.h"
#include "../ppp/odp_sink.h"
#include "../ppp/capif.h"
#include "../ppp/ppp_graph.h"
#include "../ppp/ppp_route.h"
#include "../ppp/pkt_hdrs.h"

#include "../modules/gtpu.h"
#include "../modules/ipv4.h"
#include "../modules/ethernet.h"
#ifndef NO_IPSEC
#include "../modules/ipsec.h"

struct sa_handles {
	struct sad_entry_egress *egress;
	struct sad_entry_ingress *ingress;
};
#endif

class sisu : public ppp_graph
{
	// ODP modules
	odp_src *_src;
	odp_sink_pktio *_snk_egress;
	odp_sink *_snk_ingress;

	// Packet processing modules
	gtpu *_gtp;
	ipv4 *_ip;
#ifndef NO_IPSEC
	ipsec *_ipsec;
#endif
	ethernet *_eth;

	// Control queues
	uint32_t _sync_ctrl_plane;
	odp_atomic_u32_t _sync_data_plane;
	odp_atomic_u32_t nthreads;

	// Data members targeted at pcap capturing
	bool _pcap_debug;
	capif *_cap0_egress;
	capif *_cap1_egress;
	capif *_cap2_egress;
	capif *_cap0_ingress;
	capif *_cap1_ingress;
	capif *_cap2_ingress;

public:
	sisu(const char *name,
	     uint32_t local_ip,
	     const uint8_t *local_mac,
	     bool pcap_debug);
	~sisu();

	void execute();

	// Button to stop the system
	void stop();

	// Control plane event-based communication interface
	inline void ctrl_plane_sync()
	{
		_sync_ctrl_plane++;
		while (odp_atomic_load_u32(&_sync_data_plane) !=
		      odp_atomic_load_u32(&nthreads))
			(void)0;
		odp_atomic_store_u32(&_sync_data_plane, 0);
	}

	inline void data_plane_sync(uint32_t *prev_val)
	{
		if (_sync_ctrl_plane == *prev_val)
			return;

		(*prev_val)++;
		odp_atomic_fetch_inc_u32(&_sync_data_plane);
	}

	// Interfacing with other graphs
	void attach_egress_input(odp_queue_t queue);
	void attach_egress_output(odp_pktio_t pktio);
	void attach_ingress_input(odp_queue_t queue);

	// Get information from modules
	uint32_t local_ip();
	const uint8_t *local_mac();

	// TEID handling
	uint32_t create_teid(odp_queue_t queue);
	void destroy_teid(uint32_t teid);

#ifndef NO_IPSEC
	// SA handling
	struct sad_entry_ingress *add_local_sad_entry(struct ing_sa_init_fields *fields);
	struct sad_entry_egress *add_remote_sad_entry(struct egr_sa_init_fields *fields);
	odp_crypto_session_params_t *remove_remote_sad_entry(struct sad_entry_egress *entry);
	void *remove_local_sad_entry(struct sad_entry_ingress *entry);
	odp_crypto_session_params_t *destroy_local_sad_sessions(void *to_remove);
	void register_ipsec_queue(odp_queue_t queue);
	void deregister_ipsec_queue(odp_queue_t queue);
	uint32_t sad_entry_check(struct pkt_fields *check_fields);
	void get_sa_handles(struct pkt_fields *check_fields,
			    uint32_t spi,
			    struct sa_handles *handles);
	uint32_t get_num_sa_egr();
	uint32_t get_num_sa_ing();

	// Policy handling
	bool add_spd_entry(struct spd_init_fields *fields, uint16_t position);
	bool remove_spd_entry(uint16_t position);
#endif

	// Routing table handling
	void add_ppp_route(ppp_route *route);

	// Queue context allocation
	queue_context * create_context(odp_queue_t queue);
	void destroy_context(queue_context *ctx);
};
#endif
