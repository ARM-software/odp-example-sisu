/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _SPD_H
#define _SPD_H

#include <odp.h>
#include <stdint.h>

#include "ipsec_structs.h"

#define IPSEC_MODE_TUNNEL 1
#define IPSEC_MODE_TRANSPORT 0
#define IPSEC_PROTO_ESP 1
#define IPSEC_PROTO_AH 0
#define EXTENDED_SEQUENCE_NUMBER 1
#define REGULAR_SEQUENCE_NUMBER 0
#define SPD_ENTRY_IN 0
#define SPD_ENTRY_OUT 1
#define SPD_ENTRY_INOUT 2
#define DISCARD 0
#define BYPASS 1
#define SECURE 2

struct spd_entry {
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
	struct spd_entry *next_entry;
	odp_cipher_alg_t enc_algo;
	odp_auth_alg_t auth_algo;
};

class spd
{
private:
	struct spd_entry *first_entry; // Pointer to first element in linked list
	uint16_t num_entries; // Number of entries

	// Checks if the fields in a packet match an SPD entry
	bool entry_check(struct spd_entry *entry, struct pkt_fields *check_fields);

public:
	// Adds entry in the position pointed by the int; reports status
	bool add_entry(struct spd_entry *entry, uint16_t position);

	// Adds entry at the beginning of the SPD
	void add_entry_front(struct spd_entry *entry);

	// Decouples entry at given index from SPD, returns its pointer
	struct spd_entry *remove_entry(uint16_t position);

	// Decouples first entry and returns a pointer to it
	struct spd_entry *remove_entry_front();

	// Returns the first policy corresponding with the given fields
	struct spd_entry *get_policy(struct pkt_fields *check_fields);

	// Returns pointer to the first policy in the table
	struct spd_entry *get_first_policy();

	// Returns the number of entries in the SPD
	uint16_t get_num_entries();

	spd();
	~spd();
};

#endif
