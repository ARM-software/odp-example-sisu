/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <stdint.h>
#include "ipsec.h"
#include "../instr/accounting.h"


#define IPV4_VERS_HLEN 0x45
#define IPV4_DEF_TTL 64
#define IPV4_TOS 0x00

// Random string generation using ODP
inline bool ipsec::get_rand_string(uint32_t len, uint8_t * dest)
{
	assert ( len <= 65536 && len >= 0 );
	if(! dest )
		return false;

	if(! odp_random_data(dest, len, false) )
		return false;

	return true;
}

// Verify authentication of ingress pkt
inline void ipsec::verify_auth(ppp_packet * pkt, sad_entry_ingress * sad_entry)
{
	assert( sad_entry && pkt );
	odp_packet_t odp_pkt = pkt->get_odp_pkt();

	// Set size of authentication algorithm output
	uint32_t auth_out_size;
	if( likely( sad_entry->sa_crypto_params->auth_alg == ODP_AUTH_ALG_MD5_96 ) )
		auth_out_size = MD5_96_OUT_SIZE;

	// Set authentication region within packet
	uint32_t pkt_len = pkt->length();

	uint32_t auth_len = pkt_len - auth_out_size;
	uint32_t auth_offset = 0;

	odp_crypto_data_range_t auth_range;
	odp_crypto_data_range_t enc_range;
	auth_range.length = auth_len;
	auth_range.offset = auth_offset;
	enc_range.length = 0;
	enc_range.offset = 0;

	// Operation Parameters setup
	odp_crypto_op_params_t op_params;
	op_params.hash_result_offset = pkt_len;
	op_params.pkt = op_params.out_pkt = odp_pkt;
	op_params.session = sad_entry->auth_session;
	op_params.auth_range = auth_range;
	op_params.override_iv_ptr = NULL;
	op_params.cipher_range = enc_range;

	// Set return function to continue_auth
	op_params.ctx = &odp_src_auth;

	// Make room for verification ICV
	odp_packet_push_tail(odp_pkt, auth_out_size);
	odp_bool_t posted;
	odp_crypto_op_result_t op_result;

	DEBUG_PKT("Packet sent to ICV verification");
	ACCOUNTING_END(IPSEC_INGRESS_AUTH_SETUP);

	ACCOUNTING_BEGIN();
	// Send packet to crypto accelerator
	odp_crypto_operation(&op_params, &posted, &op_result);
	ACCOUNTING_END(IPSEC_INGRESS_AUTH_CRYPTO);
}

// Encrypt and authenticate an egress packet with given parameters
inline void ipsec::encr_and_auth(ppp_packet * pkt, struct sad_entry_egress * _sad_entry,  uint32_t block_cipher_size, uint8_t * iv)
{
	assert( _sad_entry && pkt && block_cipher_size >= 0 && iv );
	ACCOUNTING_BEGIN();
	uint32_t offset_auth, offset_enc, length_auth, length_enc;

	odp_packet_t odp_pkt;
	odp_pkt = pkt->get_odp_pkt();

	// Set regions of encryption and authentication operations within packet
	length_auth = pkt->length();
	length_enc = length_auth - sizeof( struct esp_hdr ) - block_cipher_size;
	offset_auth = 0;
	offset_enc = sizeof( struct esp_hdr ) + block_cipher_size;

	odp_crypto_op_params op_params;
	// Operation Parameters setup
	{
		op_params.session = _sad_entry->enc_auth_session;

		// Output packet is the same as input packet (i.e. in-place processing)
		op_params.out_pkt = op_params.pkt = odp_pkt;

		op_params.override_iv_ptr = iv;
		op_params.hash_result_offset = length_auth;

		// Encryption and Authentication ranges
		odp_crypto_data_range_t enc_range, auth_range;
		enc_range.offset = offset_enc;
		enc_range.length = length_enc;
		op_params.cipher_range = enc_range;
		auth_range.offset = offset_auth;
		auth_range.length = length_auth;
		op_params.auth_range = auth_range;

		// Set continue_enc_auth as comeback function
		op_params.ctx = &odp_src_enc_auth;
	}

	odp_bool_t posted;
	odp_crypto_op_result_t op_result;

	// Make room for ICV
	if(_sad_entry->sa_crypto_params->auth_alg == ODP_AUTH_ALG_MD5_96)
		odp_packet_push_tail(odp_pkt, MD5_96_OUT_SIZE);
	ACCOUNTING_END(IPSEC_EGRESS_PREPARE_CRYPTO);
	DEBUG_PKT("Packet sent to encryption and authentication");

	// Start crypto operation
	ACCOUNTING_BEGIN();
	odp_crypto_operation(&op_params, &posted, &op_result);
	ACCOUNTING_END(IPSEC_EGRESS_CRYPTO);
}

// Decrypt packet using given SA
inline void ipsec::decr(ppp_packet * pkt, sad_entry_ingress * sad_entry)
{
	assert( pkt && sad_entry);

	ACCOUNTING_BEGIN();
	odp_packet_t odp_pkt = pkt->get_odp_pkt();

	uint32_t decr_size;
	uint32_t decr_offset;

	// Set IV size
	if(likely( sad_entry->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_DES || sad_entry->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_3DES_CBC ) )
		decr_offset = DES_BLOCK_SIZE;

	// Set decryption region within packet
	decr_size = pkt->length() - decr_offset;
	odp_crypto_data_range_t auth_range;
	odp_crypto_data_range_t decr_range;
	auth_range.length = 0;
	auth_range.offset = 0;
	decr_range.length = decr_size;
	decr_range.offset = decr_offset;

	// Operation parameters setup
	odp_crypto_op_params_t op_params;
	op_params.auth_range = auth_range;
	op_params.cipher_range = decr_range;
	op_params.pkt = op_params.out_pkt = odp_pkt;
	op_params.session = sad_entry->decr_session;
	op_params.override_iv_ptr = (uint8_t *) pkt->data_ptr();

	// Set return function to continue_decr
	op_params.ctx = &odp_src_decr;
	odp_bool_t posted;
	odp_crypto_op_result_t op_result;

	DEBUG_PKT("Packet sent to decryption");
	ACCOUNTING_END(IPSEC_INGRESS_DECR_SETUP);

	ACCOUNTING_BEGIN();

	// Decrypt packet
	odp_crypto_operation(&op_params, &posted, &op_result);
	ACCOUNTING_END(IPSEC_INGRESS_DECR_CRYPTO);
}

// Begin processing packet on egress path
void ipsec::input_egress_pkt(ppp_packet* pkt)
{
	ACCOUNTING_BEGIN();
	struct ipsec_bearer_context * ctx = static_cast<struct ipsec_bearer_context *>(pkt->context());

	// Get packet fields from context
	struct pkt_fields _pkt_fields;
	_pkt_fields.src_ip = ctx->src_ip;
	_pkt_fields.dest_ip = ctx->dest_ip;
	_pkt_fields.src_port = ctx->src_port;
	_pkt_fields.dest_port = ctx->dest_port;
	_pkt_fields.dscp = ctx->dscp;

	_pkt_fields.next_layer_proto = ctx->next_layer_proto;
	ACCOUNTING_END(IPSEC_EGRESS_PREPARE_LOOKUP);

	// Check SPD
	ACCOUNTING_BEGIN();
	struct spd_entry * _spd_entry = spd_table.get_policy(&_pkt_fields);

	if( unlikely(! _spd_entry) ){
		DEBUG_PKT("No policy mathing the given context fields");
		discard.enter(pkt);
		return;
	} else if( unlikely(_spd_entry->ipsec_flags.action == DISCARD) ) {
		DEBUG_PKT("Policy demands discarding packet");
		discard.enter(pkt);
		return;
	} else if( unlikely(_spd_entry->ipsec_flags.action == BYPASS) ) {
		DEBUG_PKT("Policy demands bypassing packet; IPSec processing finished");
		output_egress.enter(pkt);
		return;
	}
	ACCOUNTING_END(IPSEC_EGRESS_SPD_LOOKUP);

	// Check egress SAD
	ACCOUNTING_BEGIN();
	struct sad_entry_egress * _sad_entry = sad_table_egr.get_policy_content(&_pkt_fields);
	if( unlikely(! _sad_entry) ){
		DEBUG_PKT("No SA corresponding to context fields");
		discard.enter(pkt);
		return;
	}
	ACCOUNTING_END(IPSEC_EGRESS_SAD_LOOKUP);

	ACCOUNTING_BEGIN();
	// Pad the received packet
	uint32_t pkt_len = pkt->length();
	uint32_t block_cipher_size = 0;
	uint32_t pad_len;
	bool padding = false;

	if( likely( _sad_entry->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_DES || _sad_entry->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_3DES_CBC ) ){
		block_cipher_size = DES_BLOCK_SIZE;
		padding = true;
	}

	if (likely(padding)) {
		// Check pkt_len; at least 1 byte for pad length and 1 byte for next layer proto
		uint16_t mod = pkt_len % 8;
		if(mod < 6)
			pad_len = 8 - mod;
		else if( mod == 6 )
			pad_len = 2;
		else
			pad_len = 9;

		pkt->add_tail( (const void *) pad, pad_len);
		uint8_t * tail = (uint8_t *) pkt->get_tail_pointer();
		tail -= 2;
		tail[0] = pad_len - 2;
		tail[1] = IP_IN_IP_PROTO;
	}

	DEBUG_PKT("Padding generated");

	ACCOUNTING_END(IPSEC_EGRESS_PAD_GEN);

	// Add IV at the beginning of ciphertext
	ACCOUNTING_BEGIN();
	uint8_t * iv = (uint8_t *)pkt->grow_head(block_cipher_size);
	get_rand_string(block_cipher_size, iv);
	ACCOUNTING_END(IPSEC_EGRESS_IV_GEN);

	// Create ESP header
	ACCOUNTING_BEGIN();
	struct esp_hdr * _esp_hdr = static_cast<struct esp_hdr *>( pkt->grow_head( sizeof( struct esp_hdr ) ) );
	_esp_hdr->spi = htonl(_sad_entry->spi);
	_esp_hdr->seq_num = htonl( sad_table_egr.get_new_seq_num( _sad_entry ) );
	DEBUG_PKT("IV and ESP header generated");
	ACCOUNTING_END(IPSEC_EGRESS_ESP_GENERATION);

	// Send to encryption and authentication
	encr_and_auth(pkt, _sad_entry, block_cipher_size, iv);
}

// Begin processing packet on ingress path
void ipsec::input_ingress_pkt(ppp_packet * pkt)
{
	assert(pkt->length() > sizeof(struct ipv4hdr) + sizeof(struct esp_hdr));
	ACCOUNTING_BEGIN();
	void * p = pkt->data_ptr();
	struct ipv4hdr * ipv4_hdr = static_cast<struct ipv4hdr *>(p);

	// Check ESP header
	struct esp_hdr * _esp_hdr = (struct esp_hdr *) ( (uint8_t *) p + sizeof(struct ipv4hdr) );

	struct sad_entry_ingress * sad_entry;
	sad_entry = sad_table_ing.get_policy_content( ntohl( _esp_hdr->spi ) );

	if( (sad_entry->version & 1) == 0){
		DEBUG_PKT_1("No SA corresponding to SPI #%u", ntohl( _esp_hdr->spi ) );
		discard.enter(pkt);
		return;
	}
	ACCOUNTING_END(IPSEC_INGRESS_SAD_CHK);

	ACCOUNTING_BEGIN();
	// Verify IPv4 Header
	if ((ntohl(ipv4_hdr->dst_addr) != local_ipsec_ip) || (ipv4_hdr->vers_hlen != IPV4_VERS_HLEN) ||
		(((ipv4_hdr->tos >> 2) & DSCP_MASK) != sad_entry->dscp)) {
		DEBUG_PKT("Incorrect outer IPv4 header");
		discard.enter(pkt);
		return;
	}

	// Verify IPv4 checksum
	uint16_t chksum = ipv4_hdr->hchecksum;
	ipv4_hdr->hchecksum = 0;
	if( chksum != ipv4_hdr->checksum() ){
		DEBUG_PKT("Incorrect outer IPv4 checksum");
		discard.enter(pkt);
		return;
	}

	DEBUG_PKT("Outer IPv4 header processing successful");

	// If IPv4 Header check successful, trim header
	pkt->trim_head( sizeof( struct ipv4hdr ) );
	ACCOUNTING_END(IPSEC_INGRESS_IP_CHK);

	// Save current version of SA in temp
	pkt->temp = sad_entry->version;

	// Needs verification for authentication?
	if( sad_entry->sa_crypto_params->auth_alg != ODP_AUTH_ALG_NULL ){
		ACCOUNTING_BEGIN();
		pkt->spareptr_set(sad_entry);
		verify_auth( pkt, sad_entry );
		return;
	}

	// Needs decryption?
	if (sad_entry->sa_crypto_params->cipher_alg != ODP_CIPHER_ALG_NULL) {
		ACCOUNTING_BEGIN();
		pkt->spareptr_set(sad_entry);
		decr(pkt, sad_entry);
		return;
	}

	//Remove ESP header
	pkt->trim_head( sizeof( struct esp_hdr ) );

	DEBUG_PKT("IPSec processing successful");
	output_ingress.enter(pkt);
}

// Continue verifying the authentication
void ipsec::continue_auth(odp_event_t ev, void* op_ctx)
{
	ACCOUNTING_BEGIN();
	// Convert event to crypto operation result and free the completion event
	odp_crypto_compl_t compl_event = odp_crypto_compl_from_event(ev);
	odp_crypto_op_result_t op_result;
	odp_crypto_compl_result(compl_event, &op_result);
	ppp_packet * pkt = static_cast<ppp_packet *> (odp_packet_head(op_result.pkt));

	if(! op_result.ok){
		DEBUG_PKT("Test ICV generation failed");
		discard.enter(pkt);
		return;
	}

	odp_crypto_compl_free(compl_event);
	ACCOUNTING_END(IPSEC_INGRESS_POST_AUTH_SETUP);

	ACCOUNTING_BEGIN();
	// Retrieve SAD entry from spare pointer
	struct sad_entry_ingress * sad_entry = static_cast<struct sad_entry_ingress *> ( pkt->spareptr() );

	// Check SA version number
	if (sad_entry->version != pkt->temp) {
		DEBUG_PKT("No SA to relate to");
		discard.enter(pkt);
		return;
	}

	struct esp_hdr * _esp_hdr = static_cast<struct esp_hdr *> ( pkt->data_ptr() );

	// Set pointers to the beginning of original and verification ICV
	uint8_t * verif_icv = (uint8_t *) pkt->get_tail_pointer();
	uint8_t * original_icv;
	uint32_t icv_len;

	if(sad_entry->sa_crypto_params->auth_alg == ODP_AUTH_ALG_MD5_96)
		icv_len = MD5_96_OUT_SIZE;

	// Get sequence number of the packet
	uint32_t seq_num = ntohl(_esp_hdr->seq_num);

	// Trim ESP header
	pkt->trim_head( sizeof( struct esp_hdr ) );
	verif_icv -= icv_len;
	original_icv = verif_icv - icv_len;

	// Check that both ICVs match
	int icv_check = memcmp(verif_icv, original_icv, icv_len);

	if (icv_check) {
		DEBUG_PKT("ICV check failed");
		discard.enter(pkt);
		return;
	}

	DEBUG_PKT("ICV check successful");

	// Trim original and verification ICV
	pkt->trim_tail( 2 * icv_len );

	// Check that sequence number fits in antireplay window
	switch (check_for_replay(sad_entry->antireplay, seq_num))
	{
	case pass:
		DEBUG_PKT("Sequence Number check successful");
		break;
	case replay:
		DEBUG_PKT("Sequence number already received");
		discard.enter(pkt);
		return;
	case stale:
		DEBUG_PKT("Packet outside of antireplay window");
		discard.enter(pkt);
		return;
	}

	ACCOUNTING_END(IPSEC_INGRESS_ICV_SEN_CHK);
	decr(pkt, sad_entry);
}

// Continue after packet decryption
void ipsec::continue_decr(odp_event_t ev, void* op_ctx)
{

	ACCOUNTING_BEGIN();
	// Convert event to crypto operation result and free the completion event
	odp_crypto_compl_t compl_event = odp_crypto_compl_from_event(ev);
	odp_crypto_op_result_t op_result;
	odp_crypto_compl_result(compl_event, &op_result);
	ppp_packet * pkt = static_cast<ppp_packet *> (odp_packet_head(op_result.pkt));

	if(! op_result.ok){
		DEBUG_PKT("Decryption failed");
		discard.enter(pkt);
		return;
	}

	DEBUG_PKT("Decryption successful");
	odp_crypto_compl_free(compl_event);

	// Retrieve SAD entry from spare pointer
	struct sad_entry_ingress * sad_entry = static_cast<struct sad_entry_ingress *> ( pkt->spareptr() );

	if( sad_entry->version != pkt->temp ){
		DEBUG_PKT("No SA to relate to");
		discard.enter(pkt);
		return;
	}

	// Set IV size
	uint32_t iv_size;

	if(sad_entry->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_DES || sad_entry->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_3DES_CBC)
		iv_size = DES_BLOCK_SIZE;

	// Trim IV
	pkt->trim_head(iv_size);
	ACCOUNTING_END(IPSEC_INGRESS_POST_DECR_SETUP);

	ACCOUNTING_BEGIN();

	// Check padding
	uint8_t * tail = (uint8_t *) pkt->get_tail_pointer();
	tail -= 2;
	uint8_t nlp = tail[1];
	uint8_t pad_len = tail[0];

	// Check that the encapsulated protocol is IP-in-IP
	if( unlikely( nlp != IP_IN_IP_PROTO ) ){
		DEBUG_PKT_2("Incorrect Next Layer Protocol in padding (%u); DSCP: %u",nlp,sad_entry->dscp);
		discard.enter(pkt);
		return;
	}

	tail -= pad_len;
	if( unlikely( memcmp(tail, pad, pad_len) ) ){
		DEBUG_PKT("Incorrect padding");
		discard.enter(pkt);
		return;
	}

	// Tail correct, trim it
	pkt->trim_tail(2 + pad_len);
	DEBUG_PKT("Padding check successful");

	// Construct pkt_fields of encapsulated packet
	uint8_t * ptr = (uint8_t *) pkt->data_ptr();
	struct ipv4hdr * ipv4_hdr = (struct ipv4hdr *) ptr;
	struct udphdr * udp_hdr = (struct udphdr *) ( ptr + sizeof( struct ipv4hdr ) );
	struct pkt_fields _pkt_fields;

	_pkt_fields.src_ip = ntohl(ipv4_hdr->dst_addr);
	_pkt_fields.dest_ip = ntohl(ipv4_hdr->src_addr);
	_pkt_fields.src_port = ntohl(udp_hdr->dst_port);
	_pkt_fields.dest_port = ntohl(udp_hdr->src_port);
	_pkt_fields.dscp = (ipv4_hdr->tos >> 2) & DSCP_MASK;
	_pkt_fields.next_layer_proto = (uint8_t)ipv4_hdr->ip_proto;

	// Use pkt_fields to check SPD
	struct spd_entry * _spd_entry = spd_table.get_policy(&_pkt_fields);

	if(! _spd_entry){
		DEBUG_PKT("No policy for inner packet");
		discard.enter(pkt);
		return;
	}

	if(_spd_entry->ipsec_flags.action != SECURE){
		DEBUG_PKT("Packet handled incorrectly");
		discard.enter(pkt);
		return;
	} else if(_spd_entry->enc_algo != sad_entry->sa_crypto_params->cipher_alg || _spd_entry->auth_algo != sad_entry->sa_crypto_params->auth_alg){
		DEBUG_PKT("Packet encrypted/authenticated incorrectly");
		discard.enter(pkt);
		return;
	} else if(_spd_entry->ipsec_flags.direction == SPD_ENTRY_OUT){
		DEBUG_PKT("Policy is for outbound packets only");
		discard.enter(pkt);
		return;
	}

	// Reset spare pointer
	pkt->spareptr_set(NULL);
	ACCOUNTING_END(IPSEC_INGRESS_SPD_CHK);

	DEBUG_PKT("IPSec processing finished");
	output_ingress.enter(pkt);
}

// Continue after packet encryption and authentication
void ipsec::continue_enc_auth(odp_event_t ev, void* op_ctx)
{
	ACCOUNTING_BEGIN();
	// Convert event to crypto operation result and free the completion event
	odp_crypto_compl_t compl_event = odp_crypto_compl_from_event(ev);
	odp_crypto_op_result_t op_result;
	odp_crypto_compl_result(compl_event, &op_result);
	ppp_packet * pkt = static_cast<ppp_packet *> (odp_packet_head(op_result.pkt));

	if(! op_result.ok){
		DEBUG_PKT("Encryption and/or authentication failed");
		discard.enter(pkt);
		return;
	}

	DEBUG_PKT("Encryption and authentication successful");
	odp_crypto_compl_free(compl_event);

	struct ipsec_bearer_context * ctx = static_cast<struct ipsec_bearer_context *> (pkt->context());
	ACCOUNTING_END(IPSEC_EGRESS_FINALISE_CRYPTO);

	ACCOUNTING_BEGIN();

	// Construct new IPv4 encapsulating header
	struct ipv4hdr * ipv4_hdr = static_cast<struct ipv4hdr *>( pkt->grow_head( sizeof( struct ipv4hdr ) ) );

	ipv4_hdr->dst_addr = htonl(ctx->dest_ip);
	ipv4_hdr->src_addr = htonl(local_ipsec_ip);
	ipv4_hdr->vers_hlen = IPV4_VERS_HLEN;
	ipv4_hdr->fraginfo = 0;
	ipv4_hdr->id = 0;
	ipv4_hdr->total_len = htonl(pkt->length());
	ipv4_hdr->tos = IPV4_TOS | (ctx->dscp << 2);
	ipv4_hdr->ip_proto = PPP_IPPROTO_ESP;
	ipv4_hdr->ttl = IPV4_DEF_TTL;
	ipv4_hdr->hchecksum = 0;
	ipv4_hdr->hchecksum = ipv4_hdr->checksum();
	DEBUG_PKT("Outer IPv4 header generated");

	// Move context pointer for next module
	pkt->context_skip( sizeof( struct ipsec_bearer_context ) );
	ACCOUNTING_END(IPSEC_EGRESS_IP_GENERATION);
	DEBUG_PKT("IPSec processing finished");
	output_egress.enter(pkt);

}

// Add an egress side SA using the provided parameters
struct sad_entry_egress * ipsec::add_remote_sad_entry(struct egr_sa_init_fields * fields)
{
	assert( fields );

	struct sad_entry_egress * sad_entry = new sad_entry_egress();
	memset(sad_entry, 0, sizeof( struct sad_entry_egress ) );

	// Copy desirable fields to new SAD entry
	memcpy( &sad_entry->_pkt_fields, &fields->_pkt_fields, sizeof( struct pkt_fields ) );
	sad_entry->flags_int = fields->flags_int;
	odp_atomic_store_u32( &sad_entry->lifetime, fields->lifetime );
	sad_entry->sa_crypto_params = fields->sa_crypto_params;
	sad_entry->spi = fields->spi;
	odp_atomic_store_u32( &sad_entry->seq_cnt, 0 );
	sad_entry->sa_crypto_params->compl_queue = fields->queue;
	sad_entry->connection_counter = 1;

	// Create crypto session for encryption and authentication
	odp_crypto_session_params_t enc_auth_session_params;

	enc_auth_session_params.auth_alg = fields->sa_crypto_params->auth_alg;
	enc_auth_session_params.cipher_alg = fields->sa_crypto_params->cipher_alg;
	enc_auth_session_params.auth_cipher_text = true;
	enc_auth_session_params.auth_key.length = fields->sa_crypto_params->auth_key.length;
	enc_auth_session_params.auth_key.data = fields->sa_crypto_params->auth_key.data;
	enc_auth_session_params.cipher_key.length = fields->sa_crypto_params->cipher_key.length;
	enc_auth_session_params.cipher_key.data = fields->sa_crypto_params->cipher_key.data;
	enc_auth_session_params.compl_queue = fields->queue;
	enc_auth_session_params.op = ODP_CRYPTO_OP_ENCODE;
	enc_auth_session_params.pref_mode = ODP_CRYPTO_ASYNC;
	enc_auth_session_params.iv.data = NULL;

	if(fields->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_DES || fields->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_3DES_CBC)
		enc_auth_session_params.iv.length = DES_BLOCK_SIZE;
	else
		enc_auth_session_params.iv.length = 0;

	odp_crypto_session_t enc_auth_session;
	odp_crypto_ses_create_err_t err;
	odp_crypto_session_create(&enc_auth_session_params, &enc_auth_session, &err);
	assert( err == ODP_CRYPTO_SES_CREATE_ERR_NONE );

	// Include crypto session in SA
	sad_entry->enc_auth_session = enc_auth_session;

	// Add SA to SAD table
	sad_table_egr.add_entry(sad_entry);

	// Increase number of egress SA connections
	sa_count_egr++;

	return sad_entry;
}

// Remove an egress SA given its main parameters
odp_crypto_session_params_t * ipsec::remove_remote_sad_entry( pkt_fields * fields )
{
	assert(fields);
	uint32_t hash = sad_table_egr.hash_fields(fields);

	// Remove entry from table and retrieve it
	struct sad_entry_egress * to_delete = sad_table_egr.remove_entry(fields, hash);

	if (to_delete) {
		odp_crypto_session_destroy(to_delete->enc_auth_session);
		odp_crypto_session_params_t * to_return = to_delete->sa_crypto_params;
		to_delete->sa_crypto_params = NULL;
		delete to_delete;
		sa_count_egr--;
		return to_return;
	}
	else
		return NULL;
}

// Add SA entry in ingress SAD table, given the parameters
struct sad_entry_ingress * ipsec::add_local_sad_entry(struct ing_sa_init_fields * fields)
{
	assert(fields);
	struct sad_entry_ingress * sad_entry = new sad_entry_ingress();

	// Copy necessary fields
	sad_entry->dscp = fields->dscp;
	sad_entry->flags_int = fields->flags_int;
	sad_entry->sa_crypto_params = fields->sa_crypto_params;
	sad_entry->sa_crypto_params->compl_queue = fields->queue;
	sad_entry->antireplay = slwin_alloc();
	odp_atomic_store_u32( &sad_entry->lifetime, fields->lifetime );
	sad_entry->connection_counter = 1;
	sad_entry->version = 0;

	// Create 2 crypto sessions: 1 for verifying authentication, 1 for decryption
	odp_crypto_session_params_t auth_session_params, decr_session_params;
	auth_session_params.auth_alg = fields->sa_crypto_params->auth_alg;
	auth_session_params.auth_key.length = fields->sa_crypto_params->auth_key.length;
	auth_session_params.auth_key.data = fields->sa_crypto_params->auth_key.data;
	auth_session_params.cipher_alg = ODP_CIPHER_ALG_NULL;
	auth_session_params.compl_queue = fields->queue;
	auth_session_params.op = ODP_CRYPTO_OP_ENCODE;
	auth_session_params.pref_mode = ODP_CRYPTO_ASYNC;
	auth_session_params.auth_cipher_text = false;
	decr_session_params.auth_alg = ODP_AUTH_ALG_NULL;
	decr_session_params.cipher_alg = fields->sa_crypto_params->cipher_alg;
	decr_session_params.cipher_key.length = fields->sa_crypto_params->cipher_key.length;
	decr_session_params.cipher_key.data = fields->sa_crypto_params->cipher_key.data;
	decr_session_params.compl_queue = fields->queue;
	decr_session_params.op = ODP_CRYPTO_OP_DECODE;
	decr_session_params.pref_mode = ODP_CRYPTO_ASYNC;
	decr_session_params.iv.data = NULL;

	if(fields->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_DES || fields->sa_crypto_params->cipher_alg == ODP_CIPHER_ALG_3DES_CBC)
		decr_session_params.iv.length = DES_BLOCK_SIZE;
	else
		decr_session_params.iv.length = 0;

	odp_crypto_session_t auth_session, decr_session;
	odp_crypto_ses_create_err_t err;
	odp_crypto_session_create(&auth_session_params, &auth_session, &err);
	assert( err == ODP_CRYPTO_SES_CREATE_ERR_NONE );
	odp_crypto_session_create(&decr_session_params, &decr_session, &err);
	assert( err == ODP_CRYPTO_SES_CREATE_ERR_NONE );

	//Assign both sessions
	sad_entry->auth_session = auth_session;
	sad_entry->decr_session = decr_session;

	//Add entry to table
	uint32_t spi = sad_table_ing.add_entry(sad_entry);

	delete sad_entry;
	sa_count_ing ++;

	return sad_table_ing.get_policy_content(spi);
}

// Decouple an ingress SAD from the table
void * ipsec::remove_local_sad_entry(uint32_t spi)
{
	assert( spi >= 256 && spi <= SAD_MAX_INGRESS);
	struct sad_entry_ingress * to_remove = sad_table_ing.remove_entry( spi );

	return to_remove;
}

// Free the elements of the ingress SA
odp_crypto_session_params_t * ipsec::destroy_local_sad_sessions( void * target_sa )
{
	struct sad_entry_ingress * to_remove = static_cast<struct sad_entry_ingress *>(target_sa);
	if (to_remove) {
		odp_crypto_session_destroy(to_remove->auth_session);
		odp_crypto_session_destroy(to_remove->decr_session);
		odp_crypto_session_params_t * to_return = to_remove->sa_crypto_params;
		to_remove->sa_crypto_params = NULL;
		sa_count_ing--;

		return to_return;
	}
	else
		return NULL;
}

// Add a new rule to the SPD table
bool ipsec::add_spd_entry(struct spd_init_fields * fields, uint16_t position)
{
	assert( fields && position <= spd_table.get_num_entries() + 1 && position > 0);
	struct spd_entry * _spd_entry = new spd_entry();

	_spd_entry->auth_algo = fields->auth_algo;
	memcpy( &_spd_entry->dest_ip_range, &fields->dest_ip_range, sizeof(struct ip_range) );
	memcpy( &_spd_entry->src_ip_range, &fields->src_ip_range, sizeof(struct ip_range) );
	memcpy( &_spd_entry->dest_port_range, &fields->dest_port_range, sizeof(struct port_range) );
	memcpy( &_spd_entry->src_port_range, &fields->src_port_range, sizeof(struct port_range) );
	_spd_entry->enc_algo = fields->enc_algo;
	_spd_entry->ipsec_flags_int = fields->ipsec_flags_int;
	_spd_entry->next_layer_proto = fields->next_layer_proto;
	_spd_entry->pfp_flags_int = fields->pfp_flags_int;

	if (position == 1) {
		spd_table.add_entry_front(_spd_entry);
		return true;
	}

	return spd_table.add_entry(_spd_entry,position);
}

// Remove an SPD entry given its position
bool ipsec::remove_spd_entry(uint16_t position)
{
	if( position < 1 || position > spd_table.get_num_entries() )
		return false;

	struct spd_entry * to_delete = spd_table.remove_entry(position);

	if(! to_delete)
		delete to_delete;
	else
		return false;

	return true;
}

// Modify an SPD entry given its position and the change format
void ipsec::modify_spd_entry(uint16_t position, spd_modify_fields * fields)
{
	assert( fields && position > 0 && position <= spd_table.get_num_entries() );

	struct spd_entry * to_modify = spd_table.get_first_policy();
	uint16_t cnt = 1;

	while (cnt < position){
		to_modify = to_modify->next_entry;
		cnt++;
	}

	if( fields->ch_auth_algo == CHANGE ){
		to_modify->auth_algo = fields->fields.auth_algo;
	}
	if( fields->ch_dest_ip_range == CHANGE ){
		memcpy( &to_modify->dest_ip_range, &fields->fields.dest_ip_range, sizeof( struct ip_range ) );
	}
	if( fields->ch_dest_port_range == CHANGE ){
		memcpy( &to_modify->dest_port_range, &fields->fields.dest_port_range, sizeof( struct port_range ) );
	}
	if( fields->ch_enc_algo == CHANGE ){
		to_modify->enc_algo = fields->fields.enc_algo;
	}
	if( fields->ch_ipsec_flags == CHANGE ){
		to_modify->ipsec_flags_int = fields->fields.ipsec_flags_int;
	}
	if( fields->ch_next_layer_proto == CHANGE ){
		to_modify->next_layer_proto = fields->fields.next_layer_proto;
	}
	if( fields->ch_src_ip_range == CHANGE ){
		memcpy( &to_modify->src_ip_range, &fields->fields.src_ip_range, sizeof( struct ip_range ) );
	}
	if( fields->ch_src_port_range == CHANGE ){
		memcpy( &to_modify->src_port_range, &fields->fields.src_port_range, sizeof( struct port_range ) );
	}
}

// Check if a particular combination of fields corresponds to a particular SA
uint32_t ipsec::sad_entry_check(struct pkt_fields * check_fields)
{
	return sad_table_egr.policy_check(check_fields);
}

// Retrieve the ingress SA corresponding to a particular SPI
struct sad_entry_ingress * ipsec::get_ingress_sa( uint32_t spi )
{
	return sad_table_ing.get_policy_content( spi );
}

// Retrieve the egress SA corresponding to a particular set of "packet fields"
struct sad_entry_egress * ipsec::get_egress_sa( struct pkt_fields * check_fields )
{
	return sad_table_egr.get_policy_content( check_fields );
}

// Get the number of egress SAs
uint32_t ipsec::get_num_sa_egr()
{
	return sa_count_egr;
}

// Get the number of ingress SAs
uint32_t ipsec::get_num_sa_ing()
{
	return sa_count_ing;
}

//Set hash function for hashing egress SAs
void ipsec::set_hash(uint32_t (*funct)(struct pkt_fields * fields))
{
	assert(funct);
	sad_table_egr.set_hash(funct);
}

ipsec::ipsec(ppp_graph *_graph, const char *_name, uint32_t _local_ipsec_ip):
ppp_module(_graph, _name,"tunnel"),
sad_ing_chk(false),
sad_table_ing(&sad_ing_chk),
local_ipsec_ip(_local_ipsec_ip),
discard("discard",this),
input_ingress("input_ingress", this, (ppp_edgeP_f)&ipsec::input_ingress_pkt, 0),
input_egress("input_egress", this, (ppp_edgeP_f)&ipsec::input_egress_pkt, 0),
output_ingress("output_ingress",this, 0),
output_egress("output_egress",this, 0)
{
	sa_count_egr = 0;
	sa_count_ing = 0;
	sad_table_egr.set_hash(&murmur3);
	odp_src_decr.module = odp_src_auth.module = odp_src_enc_auth.module = this;
	odp_src_decr.function = ( void (ppp_module::*)(odp_event_t, void *) )&ipsec::continue_decr;
	odp_src_auth.function = ( void (ppp_module::*)(odp_event_t, void *) )&ipsec::continue_auth;
	odp_src_enc_auth.function = ( void (ppp_module::*)(odp_event_t, void *) )&ipsec::continue_enc_auth;

	for(int i = 0; i < MAX_PAD_SIZE; i++)
		pad[i] = i + 1;

}

ipsec::~ipsec() {}

void ipsec::traverse_outputs(void (*apply)(void *, ppp_module *, ppp_output *), void *handle)
{
	apply(handle, this, &output_ingress);
	apply(handle, this, &output_egress);
	apply(handle, this, &discard);
}
