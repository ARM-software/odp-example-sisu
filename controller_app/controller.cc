/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/comms.h"

#define MAX_LONG_OPTS 10

#define DEF_RUNTIME_S		10
#define DEF_QCI				5

#define IP_ADDR 0x01020304
const uint8_t MAC[] = {0xda, 0xf2, 0x50, 0x38, 0x83, 0xdc};

// User parameters
int runtime = DEF_RUNTIME_S;

comms c = comms(COMMS_PORT);

typedef struct {
	char *ingress;
	char *egress;
} peer_addrs_t;

static void
parse_params(int argc, char *argv[], peer_addrs_t *peers)
{
	struct option long_opts[MAX_LONG_OPTS];
	int c, n_opts = 0;

	peers->egress = NULL;
	peers->ingress = NULL;

	/* Configure the framework's options */
	long_opts[n_opts++] = (struct option){"egress", required_argument, 0, 'e'};
	long_opts[n_opts++] = (struct option){"ingress", required_argument, 0, 'i'};
	long_opts[n_opts++] = (struct option){"runtime", required_argument, 0, 'r'};
	long_opts[n_opts++] = (struct option){0, 0, 0, 0};

	int long_index = 0;
	while ((c = getopt_long(argc, argv, "e:i:r", long_opts, &long_index)) != -1) {
		switch (c) {
		case 'e':
			peers->egress = optarg;
			break;
		case 'i':
			peers->ingress = optarg;
			break;
		case 'r':
			runtime = atoi(optarg);
			break;
		default:
			goto error;
		}
	}

	if (!peers->egress || !peers->ingress) {
		fprintf(stderr, "ERROR: both --egress and --ingress IP addresses must be specified.");
		goto error;
	}

	return;

error:
	abort();
}

uint64_t create_bearer(peer_id_t peer1, peer_id_t peer2, uint32_t *teid_ptr, uint8_t qci)
{
	struct cp_msg req;
	struct cp_msg *reply;

	req.hdr.type = CP_MSG_ALLOC_TEID;
	req.alloc_teid_req.qci = qci;
	c.send_message(peer2, &req);
	reply = c.wait_for_message();
	uint32_t teid = reply->alloc_teid_rep.teid;
	printf("TEID preallocated: %u\n", teid);

	req.hdr.type = CP_MSG_CREATE_BEARER;
	req.create_bearer_req.qci = qci;
	req.create_bearer_req.remote_ip = IP_ADDR;
	req.create_bearer_req.remote_teid = teid;
	c.send_message(peer1, &req);
	reply = c.wait_for_message();
	uint64_t bearer = reply->create_bearer_rep.bearer_id;
	printf("Bearer created: %p\n", (uint8_t *)bearer);

	*teid_ptr = teid;
	return bearer;
}

void destroy_bearer(peer_id_t peer1, peer_id_t peer2, uint64_t bearer_id, uint32_t teid)
{
	struct cp_msg req;
	struct cp_msg *reply;

	req.hdr.type = CP_MSG_DESTROY_BEARER;
	req.destroy_bearer_req.bearer_id = bearer_id;
	c.send_message(peer1, &req);
	reply = c.wait_for_message();
	(void)reply;

	req.hdr.type = CP_MSG_FREE_TEID;
	req.free_teid_req.teid = teid;
	c.send_message(peer2, &req);
	reply = c.wait_for_message();

	printf("Bearer destroyed\n");
}

void create_sa(peer_id_t peer1, peer_id_t peer2, uint8_t qci)
{
	struct cp_msg req;
	struct cp_msg *reply;

	req.hdr.type = CP_MSG_CREATE_INGRESS_SA;
	req.create_ingress_sa_req.qci = qci;
	memset(&(req.create_ingress_sa_req.enc_key), 0xaa, DES3_KEY_SIZE);
	memset(&(req.create_ingress_sa_req.auth_key), 0xaa, MD5_KEY_SIZE);

	c.send_message(peer2, &req);
	reply = c.wait_for_message();
	uint64_t ingress_sa = reply->create_ingress_sa_rep.sa_id;
	uint32_t spi = reply->create_ingress_sa_rep.spi;
	(void)ingress_sa;

	req.hdr.type = CP_MSG_CREATE_EGRESS_SA;
	req.create_egress_sa_req.remote_ip = IP_ADDR;
	req.create_egress_sa_req.qci = qci;
	req.create_egress_sa_req.remote_spi = spi;
	memset(&(req.create_egress_sa_req.enc_key), 0xaa, DES3_KEY_SIZE);
	memset(&(req.create_egress_sa_req.auth_key), 0xaa, MD5_KEY_SIZE);

	c.send_message(peer1, &req);
	reply = c.wait_for_message();
	uint64_t egress_sa = reply->create_egress_sa_rep.sa_id;
	(void)egress_sa;
}

void handshake(peer_id_t peer)
{
	struct cp_msg req;
	struct cp_msg *reply;

	req.hdr.type = CP_MSG_HANDSHAKE;
	c.send_message(peer, &req);
	reply = c.wait_for_message();
	(void)reply;
}

void add_route(peer_id_t peer)
{
	struct cp_msg req;
	struct cp_msg *reply;

	req.hdr.type = CP_MSG_ADD_ROUTE;
	req.add_route_req.ip = IP_ADDR;
	req.add_route_req.length = 8;
	memcpy(&(req.add_route_req.mac), MAC, sizeof(MAC));
	c.send_message(peer, &req);
	reply = c.wait_for_message();
	(void)reply;
}

void start_pp(peer_id_t peer)
{
	struct cp_msg req;

	req.hdr.type = CP_MSG_START;
	c.send_message(peer, &req);
}

void stop_pp(peer_id_t peer)
{
	struct cp_msg req;

	req.hdr.type = CP_MSG_STOP;
	c.send_message(peer, &req);
}

int main(int argc, char *argv[])
{
	peer_addrs_t peer_addrs;

	// Parse user parameters
	parse_params(argc, argv, &peer_addrs);

	peer_id_t peer1 = c.add_peer(peer_addrs.egress);
	peer_id_t peer2 = c.add_peer(peer_addrs.ingress);

	// Handshake
	handshake(peer1);
	handshake(peer2);

	// Add routes
	add_route(peer1);

	// Create bearer
	uint32_t teid;
	create_bearer(peer1, peer2, &teid, DEF_QCI);

	// Create SA
	create_sa(peer1, peer2, DEF_QCI);

	// Start packet processing pipe
	start_pp(peer1);
	start_pp(peer2);

	// Wait for a while
	sleep(runtime);

	// Stop packet processing pipe
	stop_pp(peer1);
	stop_pp(peer2);

	return 0;
}
