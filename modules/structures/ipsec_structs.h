/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _IPSEC_STRUCTS_H
#define _IPSEC_STRUCTS_H

#include <stdint.h>
#include <odp.h>
#include <cstddef>

#define FLAG_TRUE 1
#define FLAG_FALSE 0
#define IPSEC_MODE_TUNNEL 1
#define IPSEC_MODE_TRANSPORT 0
#define IPSEC_PROTO_ESP 1
#define IPSEC_PROTO_AH 0
#define IPSEC_ESN 1
#define IPSEC_NON_ESN 0
#define IPSEC_AESCTR 0xFF
#define IPSEC_AESCBC 0x00
#define IPSEC_SHA1 0xFF
#define IPSEC_SHA256 0x00
#define SPD_DIR_IN 1
#define SPD_DIR_OUT 2
#define SPD_DIR_INOUT 3
#define SPD_DIR_NONE 0
#define SAD_EGRESS true
#define SAD_INGRESS false
#define CHANGE 1
#define KEEP 0

// IP ranges for policies;
struct ip_range {
	uint32_t base_ip;
	uint32_t mask_len;
};

// Port ranges for policies;
struct port_range {
	uint16_t max_port;
	uint16_t min_port;
};

// Packet selectors
struct pkt_fields {
	uint32_t src_ip;
	uint32_t dest_ip;
	uint16_t src_port;
	uint16_t dest_port;
	uint8_t next_layer_proto;
	uint8_t dscp;
};

// Security Association structures
struct egr_sa_init_fields {
	uint32_t spi;
	uint32_t lifetime;
	union {
		struct {
			uint8_t seq_cnt_ofl : 1;
			uint8_t antireplay : 1;
			uint8_t proto : 1;
			uint8_t mode : 1;
		} flags;
		uint8_t flags_int;
	};
	struct pkt_fields _pkt_fields;
	odp_crypto_session_params_t *sa_crypto_params;
	odp_queue_t queue;
};

struct ing_sa_init_fields {
	odp_crypto_session_params_t *sa_crypto_params;
	uint8_t dscp;
	uint32_t lifetime;
	union {
		struct {
			uint8_t seq_cnt_ofl : 1;
			uint8_t antireplay : 1;
			uint8_t proto : 1;
			uint8_t mode : 1;
		} flags;
		uint8_t flags_int;
	};
	odp_queue_t queue;
};

// Policy structures
struct spd_init_fields {
	struct ip_range src_ip_range;
	struct ip_range dest_ip_range;
	struct port_range src_port_range;
	struct port_range dest_port_range;
	uint8_t next_layer_proto;
	union {
		struct {
			uint8_t ipsec_mode : 1;
			uint8_t ipsec_proto : 1;
			uint8_t ext_seq_num : 1;
			uint8_t direction : 2;
			uint8_t action : 2;
		} ipsec_flags;
		uint8_t ipsec_flags_int;
	};
	union {
		struct {
			uint8_t pfp_src_ip : 1;
			uint8_t pfp_dest_ip : 1;
			uint8_t pfp_src_port : 1;
			uint8_t pfp_dest_port : 1;
			uint8_t pfp_next_layer_proto : 1;
		} pfp_flags;
		uint8_t pfp_flags_int;
	};
	odp_cipher_alg_t enc_algo;
	odp_auth_alg_t auth_algo;
};

struct spd_modify_fields {
	union {
		struct {
			uint8_t ch_src_ip_range : 1;
			uint8_t ch_dest_ip_range : 1;
			uint8_t ch_src_port_range : 1;
			uint8_t ch_dest_port_range : 1;
			uint8_t ch_next_layer_proto : 1;
			uint8_t ch_ipsec_flags : 1;
			uint8_t ch_enc_algo : 1;
			uint8_t ch_auth_algo : 1;
		};
	};
	struct spd_init_fields fields;
};

#endif
