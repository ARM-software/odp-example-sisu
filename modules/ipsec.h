/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _IPSEC_H
#define _IPSEC_H

#include <assert.h>

#include "structures/sad.h"
#include "structures/replayprot.h"
#include "../ppp/ppp_packet.h"
#include "../ppp/ppp_route.h"
#include "../ppp/ppp_module.h"
#include "../ppp/ppp_edge.h"
#include "../ppp/pkt_hdrs.h"
#include "../ppp/ppp_message.h"
#include "../ppp/ppp_graph.h"
#include "../ppp/odp_src.h"
#include "../instr/debug.h"

#define DES3_KEY_SIZE 24
#define DES_KEY_SIZE 7
#define DES_BLOCK_SIZE 8
#define NULL_BLOCK_SIZE 0
#define DSCP_MASK 0x3F
#define IP_IN_IP_PROTO 0x04
#define MD5_96_OUT_SIZE 12
#define MD5_KEY_SIZE 16
#define VANILLA_PACKET 0x00
#define MAX_PAD_SIZE 255

#ifdef SISU_ACCOUNTING
#define IPSEC_NSTAGES 21

#define IPSEC_STAGE_DESCS				\
"IPSec prepare lookup",				\
"IPSec SPD Lookup",					\
"IPSec SAD Lookup",					\
"IPSec paddding generation",			\
"IPSec IV generation",				\
"IPSec ESP hdr. gen.",				\
"IPSec prepare crypto op.",			\
"IPSec encrypt/authenticate.",		\
"IPSec finalise crypto op.",		\
"IPSec IP header generation",		\
"IPSec SPD check",						\
"IPSec SAD check",						\
"IPSec IP check",						\
"IPSec prepare auth crypto op.",	\
"IPSec authenticate",					\
"IPSec finalise auth crypto op.",	\
"IPSec check ESP header",				\
"IPSec prepare dec. crypto op.",	\
"IPSec decrypt",					\
"IPSec finalise decrypt crypto op.",

#define IPSEC_FIELDS				\
IPSEC_EGRESS_PREPARE_LOOKUP,		\
IPSEC_EGRESS_SPD_LOOKUP,			\
IPSEC_EGRESS_SAD_LOOKUP,			\
IPSEC_EGRESS_PAD_GEN,				\
IPSEC_EGRESS_IV_GEN,				\
IPSEC_EGRESS_ESP_GENERATION,		\
IPSEC_EGRESS_PREPARE_CRYPTO,		\
IPSEC_EGRESS_CRYPTO,				\
IPSEC_EGRESS_FINALISE_CRYPTO,		\
IPSEC_EGRESS_IP_GENERATION,			\
IPSEC_INGRESS_SPD_CHK,				\
IPSEC_INGRESS_SAD_CHK,				\
IPSEC_INGRESS_IP_CHK,				\
IPSEC_INGRESS_AUTH_SETUP,			\
IPSEC_INGRESS_AUTH_CRYPTO,			\
IPSEC_INGRESS_POST_AUTH_SETUP,		\
IPSEC_INGRESS_ICV_SEN_CHK,			\
IPSEC_INGRESS_DECR_SETUP,			\
IPSEC_INGRESS_DECR_CRYPTO,			\
IPSEC_INGRESS_POST_DECR_SETUP,
#endif

struct ipsec_bearer_context {
	uint32_t src_ip;
	uint32_t dest_ip;
	uint8_t dscp;
	uint16_t src_port;
	uint16_t dest_port;
	uint8_t next_layer_proto;
};

struct esp_hdr {
	uint32_t spi;
	uint32_t seq_num;
};

class ipsec : public ppp_module
{
	bool sad_ing_chk;

	sad_egress sad_table_egr;
	sad_ingress sad_table_ing;
	uint32_t sa_count_egr, sa_count_ing;
	odp_src_input odp_src_decr, odp_src_auth, odp_src_enc_auth;

	spd spd_table;

	const uint32_t local_ipsec_ip;
	uint8_t pad[MAX_PAD_SIZE];

	// Generate a string of len random bytes starting at address dest
	inline bool get_rand_string(uint32_t len, uint8_t *dest);

	// Increment the iv at position src and copy it in dest
	inline void inc_iv(uint32_t len, uint8_t *src, uint8_t *dest);

	// Per packet encryption and authentication function
	inline void encr_and_auth(ppp_packet *pkt,
				  struct sad_entry_egress *_sad_entry,
				  uint32_t block_cipher_size,
				  uint8_t *iv);

	// Generate new verification ICV for pkt
	inline void verify_auth(ppp_packet *pkt,
				struct sad_entry_ingress *sad_entry);

	// Decrypt pkt
	inline void decr(ppp_packet *pkt, struct sad_entry_ingress *sad_entry);

	void control_evt(odp_event_t event);

	// Begin processing an inbound packet on ingress path
	void input_ingress_pkt(ppp_packet *pkt);

	// Begin processing an inbound pakcet on egress path
	void input_egress_pkt(ppp_packet *pkt);

public:
	// Add SA to egress SAD, given its fields
	struct sad_entry_egress *add_remote_sad_entry(struct egr_sa_init_fields *fields);

	// Remove SA from egress SAD, given its fields
	odp_crypto_session_params_t *remove_remote_sad_entry(struct pkt_fields *fields);

	// Add SA to ingress SAD and return its assigned SPI
	struct sad_entry_ingress *add_local_sad_entry(struct ing_sa_init_fields *fields);

	// Remove SA from ingress SAD given its SPI
	void *remove_local_sad_entry(uint32_t spi);

	// Destroy sessions for given handle to ingress SAD
	odp_crypto_session_params_t *destroy_local_sad_sessions(void *to_remove);

	// Add policy to the SPD given its fields and its position
	bool add_spd_entry(struct spd_init_fields *fields, uint16_t position);

	// Remove policy from SPD given its position
	bool remove_spd_entry(uint16_t position);

	// Modify policy from SPD given its position, the new fields and the
	// change mask
	void modify_spd_entry(uint16_t position,
			      struct spd_modify_fields *fields);

	// Set hash function for use in egress SAD hashing; options: murmur3,
	// fast_hash;
	void set_hash(uint32_t (*funct)(struct pkt_fields *fields));

	// Check for the existence of an SAD entry that matches the fields
	uint32_t sad_entry_check(struct pkt_fields *check_fields);

	// Return SA handle with given SPI
	struct sad_entry_ingress *get_ingress_sa(uint32_t spi);

	// Return SA handle with given packet fields
	struct sad_entry_egress *get_egress_sa(struct pkt_fields *check_fields);

	// Get number of egress SA entries
	uint32_t get_num_sa_egr();

	// Get number of ingress SA entries
	uint32_t get_num_sa_ing();

	// Verify the newly generated ICV against the received one and trim it
	// and ESP header
	void continue_auth(odp_event_t ev, void *op_ctx);

	// Remove IV, check and remove padding, check SPD and send to output
	void continue_decr(odp_event_t ev, void *op_ctx);

	// Add IPv4 header and send to output
	void continue_enc_auth(odp_event_t ev, void *op_ctx);

	ppp_outputP discard;

	ppp_inputP input_ingress;
	ppp_inputP input_egress;

	ppp_outputP output_ingress;
	ppp_outputP output_egress;

	ipsec(ppp_graph *_graph, const char *_name, uint32_t _local_ipsec_ip);
	~ipsec();

	void traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *),
			      void *);
};

#endif
