/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <unistd.h>
#include <math.h>

#include "cpagent.h"
#include "../instr/debug.h"
#include "../ppp/ppp_pktpool.h"

#define TEAR_DOWN_WAIT 5
#define NS_IN_S 1000000000ull
#define NS_IN_MS 1000000ull

#define MAX_N_BEARERS (1 << 16)
#define DEF_BEARER_QCI 7
#define GTPU_PORT 2152
#define ENC_AUTH

// List of DSCPs/PCPs
uint8_t dscp_list[] = {0, 10, 18, 28, 26, 34, 46, 2};
uint8_t pcp_list[] = {0, 1, 2, 3, 3, 4, 5, 3};

queue_set sisu_input, sisu_output, sisu_ipsec_egr, sisu_ipsec_ingr;

// Create ODP queue in the appropriate schedule group
static odp_queue_t create_queue(ppp_graph *g, const char *name)
{
	odp_queue_t queue;
	odp_queue_param_t qparam;

	odp_queue_param_init(&qparam);
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = odp_schedule_group_lookup(g->name);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	FATAL_ERROR_COND(qparam.sched.group == ODP_SCHED_GROUP_INVALID, "odp_schedule_group_lookup");

	qparam.context = NULL;

	queue = odp_queue_create(name, &qparam);

	FATAL_ERROR_COND(queue == ODP_QUEUE_INVALID, "odp_queue_create");

	return queue;
}

static odp_pktio_t create_pktin(sisu *_sisu, const char *dev, odp_pool_t pool)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DISABLED;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);

	if (pktio == ODP_PKTIO_INVALID) {
		exit(0);
	}

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	pktin_param.queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	pktin_param.queue_param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	pktin_param.queue_param.sched.group = odp_schedule_group_lookup(_sisu->name);

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		exit(0);
	}

	odp_queue_t queue_in;
	odp_pktin_event_queue(pktio, &queue_in, 1);

	_sisu->create_context(queue_in);
	_sisu->attach_ingress_input(queue_in);

	ret = odp_pktio_start(pktio);
	if (ret)
		exit(0);

	return pktio;
}

static odp_pktio_t create_pktout(sisu *_sisu, const char *dev, odp_pool_t pool)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktout_queue_param_t pktout_param;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DISABLED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);

	if (pktio == ODP_PKTIO_INVALID) {
		exit(0);
	}

	odp_pktout_queue_param_init(&pktout_param);

	if (odp_pktout_queue_config(pktio, &pktout_param)) {
		exit(0);
	}

	_sisu->attach_egress_output(pktio);

	ret = odp_pktio_start(pktio);
	if (ret)
		exit(0);

	return pktio;
}

// ODP Queues can not be destroyed unless empty.
// This function drains and then destroys a queue
static inline void destroy_queue(odp_queue_t queue)
{
	odp_event_t ev = odp_queue_deq(queue);
	while ((ev = odp_queue_deq(queue)) != ODP_EVENT_INVALID) {
		odp_event_free(ev);
	};

	int rc;
	rc = odp_queue_destroy(queue);
	if (rc < 0)
		perror("odp_queue_destroy"), abort();
}

// Terminate all of the graphs.
// This function is called when
// end_timer expires
void cpagent::stop()
{
	printf("Stopping traffic generator\n");
	_tgen->stop();

	printf("Stopping SISU instance\n");
	_sisu->stop();

	printf("Stopping traffic terminator\n");
	_tterm->stop();
}

#ifndef NO_IPSEC
void cpagent::create_policy(uint32_t src_ip_base, uint32_t src_ip_mask_len, uint32_t dest_ip_base, uint32_t dest_ip_mask_len,
					   uint16_t min_port, uint16_t max_port, uint8_t next_layer_proto, uint8_t action,
					   odp_cipher_alg_t cipher_alg, odp_auth_alg_t auth_alg, uint16_t position)
{
	struct spd_init_fields spd_fields;

	spd_fields.src_ip_range.base_ip = src_ip_base;
	spd_fields.src_ip_range.mask_len = src_ip_mask_len;
	spd_fields.dest_ip_range.base_ip = dest_ip_base;
	spd_fields.dest_ip_range.mask_len = dest_ip_mask_len;
	spd_fields.src_port_range.min_port = min_port;
	spd_fields.src_port_range.max_port = max_port;
	spd_fields.dest_port_range.min_port = min_port;
	spd_fields.dest_port_range.max_port = max_port;
	spd_fields.next_layer_proto = next_layer_proto;
	spd_fields.ipsec_flags.direction = SPD_DIR_INOUT;
	spd_fields.ipsec_flags.action = action;
	spd_fields.enc_algo = cipher_alg;
	spd_fields.auth_algo = auth_alg;

	_sisu->add_spd_entry(&spd_fields, position);
}

static odp_crypto_session_params_t *get_enc_auth_params()
{
	odp_crypto_session_params_t *params;
	params = new odp_crypto_session_params_t();
	memset(params, 0, sizeof(struct odp_crypto_session_params));

#ifdef ENC_AUTH
	params->auth_alg = ODP_AUTH_ALG_MD5_96;
	params->cipher_alg = ODP_CIPHER_ALG_3DES_CBC;
#else
	params->auth_alg = ODP_AUTH_ALG_NULL;
	params->cipher_alg = ODP_CIPHER_ALG_NULL;
#endif

	params->auth_key.data = new uint8_t[MD5_KEY_SIZE];
	params->auth_key.length = MD5_KEY_SIZE;
	params->cipher_key.data = new uint8_t[DES3_KEY_SIZE];
	params->cipher_key.length = DES3_KEY_SIZE;

	return params;
}

struct sad_entry_ingress * cpagent::create_sa_ingress(uint8_t qci, uint8_t *enc_key, uint8_t *auth_key)
{
	struct ing_sa_init_fields ing_fields;

	memset(&ing_fields, 0, sizeof(struct ing_sa_init_fields));

	ing_fields.dscp = dscp_list[qci];
	ing_fields.flags_int = 0x00;
	ing_fields.sa_crypto_params = get_enc_auth_params();
	memcpy( ing_fields.sa_crypto_params->cipher_key.data, enc_key, ing_fields.sa_crypto_params->cipher_key.length );
	memcpy( ing_fields.sa_crypto_params->auth_key.data, auth_key, ing_fields.sa_crypto_params->auth_key.length );

	ing_fields.queue = sisu_ipsec_ingr[qci];

	struct sad_entry_ingress *sa;
	sa = _sisu->add_local_sad_entry(&ing_fields);

	return sa;
}

struct sad_entry_egress * cpagent::create_sa_egress(uint32_t spi, uint32_t dest_ip, uint8_t qci, uint8_t * enc_key, uint8_t * auth_key)
{
	struct egr_sa_init_fields egr_fields;

	memset(&egr_fields, 0, sizeof(struct egr_sa_init_fields));

	// Initialize fields to be passed for SA creation
	egr_fields.sa_crypto_params = get_enc_auth_params();
	memcpy( egr_fields.sa_crypto_params->cipher_key.data, enc_key, egr_fields.sa_crypto_params->cipher_key.length );
	memcpy( egr_fields.sa_crypto_params->auth_key.data, auth_key, egr_fields.sa_crypto_params->auth_key.length );

	// Pick ODP queue
	egr_fields.queue = sisu_ipsec_egr[qci];

	egr_fields.spi = spi;
	egr_fields._pkt_fields.src_ip = _sisu->local_ip();
	egr_fields._pkt_fields.dest_ip = dest_ip;
	egr_fields._pkt_fields.src_port = GTPU_PORT;
	egr_fields._pkt_fields.dest_port = GTPU_PORT;
	egr_fields._pkt_fields.next_layer_proto = IPPROTO_UDP;
	egr_fields._pkt_fields.dscp = dscp_list[qci];
	egr_fields.flags_int = 0x00;

	struct sad_entry_egress *sa;
	sa = _sisu->add_remote_sad_entry(&egr_fields);

	return sa;
}
#endif

#ifndef NO_IPSEC
/*static void destroy_sa_ingress(sisu* peer, struct sad_entry_ingress *ingress_sa)
{
	ingress_sa->connection_counter--;

	if (!(ingress_sa->connection_counter)) {
		odp_crypto_session_params_t *params = ingress_sa->sa_crypto_params;
		void * to_remove = peer->remove_local_sad_entry(ingress_sa);

		peer->ctrl_plane_sync();
		peer->destroy_local_sad_sessions(to_remove);

		delete params->auth_key.data;
		delete params->cipher_key.data;
		delete params;
	}
}

static void destroy_sa_egress(sisu* peer, struct sad_entry_egress *egress_sa)
{
	egress_sa->connection_counter--;

	if (!(egress_sa->connection_counter)) {
		odp_crypto_session_params_t *params = egress_sa->sa_crypto_params;
		peer->remove_remote_sad_entry(egress_sa);

		delete params->auth_key.data;
		delete params->cipher_key.data;
		delete params;
	}
}*/
#endif

peer_bearer_t cpagent::create_bearer(uint8_t qci, uint32_t remote_ip, uint32_t remote_teid)
{
	peer_bearer_t bearer;
	bearer = new struct peer_bearer;

	// Fill context
	bearer->ctx = new bearer_context;
	bearer->ctx->tgen.queue = sisu_input[qci];
	bearer->ctx->gtpu.dst_ip = remote_ip;
	bearer->ctx->gtpu.teid = remote_teid;
	bearer->ctx->ipv4.dst_ip = remote_ip;
	bearer->ctx->ipv4.dscp = dscp_list[qci];

#ifndef NO_IPSEC
	bearer->ctx->ipsec.src_ip = _sisu->local_ip();
	bearer->ctx->ipsec.dest_ip = remote_ip;
	bearer->ctx->ipsec.dscp = dscp_list[qci];
	bearer->ctx->ipsec.src_port = GTPU_PORT;
	bearer->ctx->ipsec.dest_port = GTPU_PORT;
	bearer->ctx->ipsec.next_layer_proto = PPP_IPPROTO_UDP;
#endif

	// Determine PCP from DSCP
	bearer->ctx->eth.pcp = pcp_list[qci];

	// Enable generators
	_tgen->start_flow(bearer->ctx);

	_n_bearers++;
	return bearer;
}

void cpagent::destroy_bearer(peer_bearer_t bearer)
{
	// Stop traffic generators
	_tgen->stop_flow(bearer->ctx);

	// Control plane sync
	_sisu->ctrl_plane_sync();

	// Delete bearer
	delete bearer->ctx;
	delete bearer;
	_n_bearers--;
}

void cpagent::enter_configure_mode()
{
	struct cp_msg *req;
	struct cp_msg reply;

	while (1) {
		req = _comms->wait_for_message();

		switch(req->hdr.type) {
		case CP_MSG_START:
			printf("START Message received.\n");
			goto end;
		case CP_MSG_STOP:
			printf("STOP Message received.\n");
			stop();
			goto end;
		case CP_MSG_ALLOC_TEID:
			printf("Alloc TEID Message received.\n");
			reply.hdr.type = CP_MSG_ALLOC_TEID;
			reply.alloc_teid_rep.teid = _sisu->create_teid(sisu_output[req->alloc_teid_req.qci]);
			_comms->send_message(0, &reply);
			break;
		case CP_MSG_FREE_TEID:
			printf("Free TEID Message received.\n");
			reply.hdr.type = CP_MSG_FREE_TEID;
			_sisu->destroy_teid(req->free_teid_req.teid);
			_comms->send_message(0, &reply);
			break;
		case CP_MSG_CREATE_BEARER:
			printf("Create bearer Message received.\n");
			reply.hdr.type = CP_MSG_CREATE_BEARER;
			reply.create_bearer_rep.bearer_id = (uint64_t)create_bearer(req->create_bearer_req.qci, req->create_bearer_req.remote_ip, req->create_bearer_req.remote_teid);
			printf("Bearer created: %p\n", (void *)reply.create_bearer_rep.bearer_id);
			_comms->send_message(0, &reply);
			break;
		case CP_MSG_DESTROY_BEARER:
			printf("Destroy bearer Message received.\n");
			reply.hdr.type = CP_MSG_DESTROY_BEARER;
			destroy_bearer((peer_bearer_t)(req->destroy_bearer_req.bearer_id));
			_comms->send_message(0, &reply);
			break;
#ifndef NO_IPSEC
		case CP_MSG_CREATE_EGRESS_SA:
			printf("Create egress sa Message received.\n");
			reply.hdr.type = CP_MSG_CREATE_EGRESS_SA;
			reply.create_egress_sa_rep.sa_id = (uint64_t)create_sa_egress(req->create_egress_sa_req.remote_spi, req->create_egress_sa_req.remote_ip, req->create_egress_sa_req.qci, req->create_egress_sa_req.enc_key, req->create_egress_sa_req.auth_key);
			printf("egress sa created: %p\n", (void *)reply.create_egress_sa_rep.sa_id);
			_comms->send_message(0, &reply);
			break;
		case CP_MSG_CREATE_INGRESS_SA:
			printf("Create ingress sa Message received.\n");
			reply.hdr.type = CP_MSG_CREATE_INGRESS_SA;
			struct sad_entry_ingress *sa;
			sa = create_sa_ingress(req->create_ingress_sa_req.qci, req->create_ingress_sa_req.enc_key, req->create_ingress_sa_req.auth_key);
			reply.create_ingress_sa_rep.sa_id = (uint64_t)sa;
			reply.create_ingress_sa_rep.spi = sa->spi;
			printf("ingress sa created: %p\n", (void *)reply.create_ingress_sa_rep.sa_id);
			_comms->send_message(0, &reply);
			break;
#endif
		case CP_MSG_ADD_ROUTE:
			printf("Create route Message received %u, %u.\n", req->add_route_req.ip, req->add_route_req.length);
			reply.hdr.type = CP_MSG_ADD_ROUTE;
			_sisu->add_ppp_route(new ppp_route(req->add_route_req.ip, req->add_route_req.length, rt_remote, 0, 0x12345678, ETH_ADDR_SIZE, (unsigned char *)req->add_route_req.mac));
			printf("Route added.\n");
			_comms->send_message(0, &reply);
			break;
		default:
			printf("Unrecognized message type received: %d.\n", req->hdr.type);
		}
	}

	end:

	return;
}

cpagent::cpagent(tgen *tgen_instance, sisu *sisu_instance, tterm *tterm_instance, char *in_iface, char *out_iface) :
	   _tgen(tgen_instance), _sisu(sisu_instance), _tterm(tterm_instance)
{
	// Create packet pool
	odp_pool_param_t params;
	odp_pool_param_init(&params);
	params.pkt.seg_len = 1856;
	params.pkt.len = 1856;
	params.pkt.num = (512 * 2048) / 1856;
	params.type = ODP_POOL_PACKET;

	_pool_in = odp_pool_create("packet_pool", &params);

	// Create pktio interfaces
	_pktio_in = create_pktin(_sisu, in_iface, _pool_in);
	_pktio_out = create_pktout(_sisu, out_iface, _pool_in);

	// Create input and output queues
	for (int i = 0; i < N_QCIS; i++) {
		sisu_input[i] = create_queue(_sisu, "sisu in");
		_sisu->create_context(sisu_input[i]);
		_sisu->attach_egress_input(sisu_input[i]);
		sisu_output[i] = create_queue(_tterm, "sisu out");
		_tterm->create_context(sisu_output[i]);
		_tterm->start_flow(sisu_output[i]);

		sisu_ipsec_egr[i] = create_queue(_sisu, "sisu ipsec egr");
		_sisu->create_context(sisu_ipsec_egr[i]);
		sisu_ipsec_ingr[i] = create_queue(_sisu, "sisu ipsec ingr");
		_sisu->create_context(sisu_ipsec_ingr[i]);
	}

#ifndef NO_IPSEC
	// Initialize SPD
	create_policy(_sisu->local_ip(), 0, _sisu->local_ip(), 0, 0, (1 << 16) - 1, IPPROTO_UDP, SECURE, ODP_CIPHER_ALG_3DES_CBC, ODP_AUTH_ALG_MD5_96, 1);
#endif

	_n_bearers = 0;

	odp_pktio_promisc_mode_set(_pktio_in, true);

	// Create comms interface for control-plane interaction
	_comms = new comms(COMMS_PORT, true);
}

cpagent::~cpagent()
{
	// Stop pktio interfaces
	odp_pktio_stop(_pktio_in);
	odp_pktio_stop(_pktio_out);

	// Free resources
	odp_pktio_close(_pktio_in);
	odp_pktio_close(_pktio_out);

	odp_pool_destroy(_pool_in);
	destroy_queue(_queue_in);

	for (int i = 0; i < N_QCIS; i++) {
		destroy_queue(sisu_input[i]);
		destroy_queue(sisu_output[i]);
		destroy_queue(sisu_ipsec_egr[i]);
		destroy_queue(sisu_ipsec_ingr[i]);
	}
}
