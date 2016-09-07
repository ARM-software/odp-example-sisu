/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _SAD_H
#define _SAD_H

#include <stack>
#include <stdint.h>
#include <cstddef>
#include <vector>
#include <odp.h>

#include "ipsec_structs.h"
#include "spd.h"

#define SEED 0xc709b658

#define SAD_MAX_EGRESS 997 // Must be prime
#define SAD_MAX_INGRESS 1500

// Hash functions
uint32_t murmur3(struct pkt_fields *fields);
uint32_t fast_hash(struct pkt_fields *fields);

struct sad_entry_egress {
	struct pkt_fields _pkt_fields;
	uint32_t spi;
	uint32_t hash;
	odp_crypto_session_params_t *sa_crypto_params;
	odp_crypto_session_t enc_auth_session;
	struct sad_entry_egress *next_entry;
	union {
		struct {
			uint8_t seq_cnt_ofl : 1;
			uint8_t antireplay : 1;
			uint8_t proto : 1;
			uint8_t mode : 1;
		} flags;
		uint8_t flags_int;
	};
	odp_atomic_u32_t seq_cnt;
	odp_atomic_u32_t lifetime;
	uint16_t connection_counter;
};

struct sad_entry_ingress {
	struct sliding_window *antireplay;
	uint32_t spi;
	odp_atomic_u32_t lifetime;
	odp_crypto_session_params_t *sa_crypto_params;
	odp_crypto_session_t auth_session;
	odp_crypto_session_t decr_session;
	union {
		struct {
			uint8_t seq_cnt_ofl : 1;
			uint8_t antireplay : 1;
			uint8_t proto : 1;
			uint8_t mode : 1;
		} flags;
		uint8_t flags_int;
	};
	uint8_t dscp;
	uint8_t next_layer_proto;
	uint16_t connection_counter;
	uint16_t version;
};

class sad_egress
{
private:
	struct sad_entry_egress *sad_table_egress[SAD_MAX_EGRESS];

	// Hash function callback
	uint32_t (*hash_funct)(struct pkt_fields *fields);

public:
	// Remove an entry based on the fields that require checking and on its hash value
	struct sad_entry_egress *remove_entry(struct pkt_fields *check_fields, uint32_t hash);

	// Obtain the hash value for the given set of inputs
	uint32_t hash_fields(struct pkt_fields *fields);

	// Add the SAD entry with the given hash
	bool add_entry(struct sad_entry_egress *entry);

	// Get sequence number
	uint32_t get_new_seq_num(struct sad_entry_egress *entry);

	// Set the hash function callback
	void set_hash(uint32_t (*funct)(struct pkt_fields *fields));

	// Find the policy content with the given hash
	struct sad_entry_egress *get_policy_content(struct pkt_fields *check_fields);

	// Verify the existence of a policy content with the given parameters
	uint32_t policy_check(struct pkt_fields *check_fields);

	sad_egress();
};

class sad_ingress
{
private:
	struct sad_entry_ingress sad_table_ingress[SAD_MAX_INGRESS];
	std::stack<uint32_t, std::vector<int> > spi_stack;

	// Get the first SPI in the stack
	uint32_t get_new_spi();

public:

	// Remove an entry based on the fields that require checking and on its SPI value
	struct sad_entry_ingress *remove_entry(uint32_t spi);

	// Add SAD entry assigning it an SPI and return the SPI
	uint32_t add_entry(struct sad_entry_ingress *entry);

	// Find the policy content with the given SPI
	struct sad_entry_ingress *get_policy_content(uint32_t spi);

	sad_ingress(bool *ready_flag);
	~sad_ingress();
};

#endif
