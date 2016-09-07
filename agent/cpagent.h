/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _CPAGENT_H
#define _CPAGENT_H

#include <stdint.h>
#include <list>

#include "../ppp/globals.h"
#include "../graphs/tgen.h"
#include "../graphs/tterm.h"
#include "../graphs/sisu.h"

#include "cpmessages.h"
#include "../lib/comms.h"

#define N_QCIS 8

extern uint8_t dscp_list[N_QCIS];
extern uint8_t pcp_list[N_QCIS];

typedef odp_queue_t queue_set[N_QCIS];

// Only the control plane understands the concept of bearer
struct peer_bearer {
	class bearer_context *ctx;
	uint32_t teid;
#ifndef NO_IPSEC
	struct sad_entry_egress *egress_sa;
	struct sad_entry_ingress *ingress_sa;
#endif
};

typedef struct peer_bearer *peer_bearer_t;

class bearer_context
{
public:
	struct tgen_bearer_context tgen;
	struct gtpu_bearer_context gtpu;
	struct ipv4_bearer_context ipv4;
#ifndef NO_IPSEC
	struct ipsec_bearer_context ipsec;
#endif
	struct ethernet_bearer_context eth;
};

// Technically, the control plane is associated with one peer,
// and it communicates with the other peer's control plane
// However, since we don't have a real control plane,
// this is rather a glorified CP that also knows how to generate and
// terminate traffic via traffic generators and terminators

class cpagent
{
	tgen *_tgen;
	sisu *_sisu;
	tterm *_tterm;

	comms *_comms;

	uint32_t _n_bearers;

	// ODP handlers
	odp_pktio_t _pktio_in, _pktio_out;
	odp_pool_t _pool_in;
	odp_queue_t _queue_in;

	// Private functions
	void stop();
	void destroy_bearer(peer_bearer_t bearer);
	void create_connection_handler(odp_event_t evt, void *ctx);
	void destroy_connection_handler(odp_event_t evt, void *ctx);

public:
	cpagent(tgen *tgen,
		sisu *sisu,
		tterm *tterm,
		char *in_iface,
		char *out_iface);
	~cpagent();

	void enter_configure_mode();
	peer_bearer_t create_bearer(uint8_t dscpu,
				    uint32_t remote_ip,
				    uint32_t remote_teid);
	void tear_down_connection(peer_bearer_t);

#ifndef NO_IPSEC
	//location is assigned as ENB or SGW as defined above; position is the
	//position in the SPD table of the policy; src and dest ip ranges are
	//single IPs, with other end as base
	struct sad_entry_ingress *create_sa_ingress(uint8_t qci,
						    uint8_t *enc_key,
						    uint8_t *auth_key);
	struct sad_entry_egress *create_sa_egress(uint32_t spi,
						  uint32_t dest_ip,
						  uint8_t qci,
						  uint8_t *enc_key,
						  uint8_t *auth_key);
	void create_policy(uint32_t src_ip_base,
			   uint32_t src_ip_mask_len,
			   uint32_t dest_ip_base,
			   uint32_t dest_ip_mask_len,
			   uint16_t min_port,
			   uint16_t max_port,
			   uint8_t next_layer_proto,
			   uint8_t action,
			   odp_cipher_alg_t cipher_alg,
			   odp_auth_alg_t auth_alg,
			   uint16_t position);
#endif
};

#endif
