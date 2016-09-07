/* Copyright 2016, ARM Limited or its affiliates. All rights reserved. */

#ifndef _CPMESSAGES_H
#define _CPMESSAGES_H

#include <stdint.h>

#define DES3_KEY_SIZE 24
#define MD5_KEY_SIZE 16

enum cp_msg_type {
	CP_MSG_HANDSHAKE,
	CP_MSG_START,
	CP_MSG_STOP,
	CP_MSG_ALLOC_TEID,
	CP_MSG_FREE_TEID,
	CP_MSG_CREATE_BEARER,
	CP_MSG_DESTROY_BEARER,
	CP_MSG_ADD_ROUTE,
	CP_MSG_CREATE_EGRESS_SA,
	CP_MSG_CREATE_INGRESS_SA,
	CP_MSG_N,
};

// Message header
struct cp_msg_hdr {
	uint32_t preamble;
	uint8_t type;
	uint8_t padding[2];
};

// Alloc TEID request message
struct cp_msg_alloc_teid_req {
	uint8_t qci;
};

// Alloc TEID reply message
struct cp_msg_alloc_teid_rep {
	uint32_t teid;
};

// Free TEID request message
struct cp_msg_free_teid_req {
	uint32_t teid;
};

// Create bearer request message
struct cp_msg_create_bearer_req {
	uint8_t qci;
	uint32_t remote_ip;
	uint32_t remote_teid;
};

// Create bearer reply message
struct cp_msg_create_bearer_rep {
	uint64_t bearer_id;
};

// Destroy bearer request message
struct cp_msg_destroy_bearer_req {
	uint64_t bearer_id;
};

// Add route request message
struct cp_msg_add_route_req {
	uint32_t ip;
	uint8_t mac[6];
	uint8_t length;
};

// Create egress SA request message
struct cp_msg_create_egress_sa_req {
	uint8_t qci;
	uint32_t remote_spi;
	uint32_t remote_ip;
	uint8_t enc_key[DES3_KEY_SIZE];
	uint8_t auth_key[MD5_KEY_SIZE];
};

// Create egress SA reply message
struct cp_msg_create_egress_sa_rep {
	uint64_t sa_id;
};

// Create ingress SA request message
struct cp_msg_create_ingress_sa_req {
	uint8_t qci;
	uint8_t enc_key[DES3_KEY_SIZE];
	uint8_t auth_key[MD5_KEY_SIZE];
};

// Create egress SA reply message
struct cp_msg_create_ingress_sa_rep {
	uint64_t sa_id;
	uint32_t spi;
};

// Message
struct cp_msg {
	struct cp_msg_hdr hdr;
	union {
		struct cp_msg_alloc_teid_req alloc_teid_req;
		struct cp_msg_alloc_teid_rep alloc_teid_rep;
		struct cp_msg_free_teid_req free_teid_req;
		struct cp_msg_create_bearer_req create_bearer_req;
		struct cp_msg_create_bearer_rep create_bearer_rep;
		struct cp_msg_destroy_bearer_req destroy_bearer_req;
		struct cp_msg_add_route_req add_route_req;
		struct cp_msg_create_egress_sa_req create_egress_sa_req;
		struct cp_msg_create_egress_sa_rep create_egress_sa_rep;
		struct cp_msg_create_ingress_sa_req create_ingress_sa_req;
		struct cp_msg_create_ingress_sa_rep create_ingress_sa_rep;
	};
};

#endif
