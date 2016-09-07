/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <iostream>
#include <stdio.h>

#include "sad.h"

// Murmur3 Hash function; based on MU(ltiply) and R(otate)
uint32_t murmur3(struct pkt_fields * fields)
{
	uint32_t seed = fields->src_ip ^ fields->dest_ip ^ SEED;

	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;
	const uint32_t r1 = 15;
	const uint32_t r2 = 13;
	const uint32_t m = 5;
	const uint32_t n = 0xe6546b64;

	const uint32_t length = sizeof(pkt_fields);
	const char * key = (const char *) fields;

	uint32_t hash = seed;

	uint32_t nBlocks = length / 4; //process in blocks of 32 bits;

	uint32_t * blocks = (uint32_t *) key;

	for(uint32_t i = 0; i < nBlocks; i++) {
		uint32_t k = blocks[i];
		k *= c1;
		k = (k << r1) | (k >> (32 - r1));
		k *= c2;

		hash ^= k;
		hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
	}

	hash ^= length;
	hash ^= (hash >> 16);
	hash *= 0x85ebca6b;
	hash ^= (hash >> 13);
	hash *= 0xc2b2ae35;
	hash ^= (hash >> 16);

	return hash;
}

// Simple, fast hash, meant to check the efficiency of Murmur3
uint32_t fast_hash(struct pkt_fields * fields)
{
	uint32_t hash = fields->src_ip ^ fields->dest_ip ^ SEED;
	hash = hash ^ fields->dest_port;
	hash = hash ^ (fields->src_port << 16);
	hash = hash ^ (fields->dscp * fields->next_layer_proto);

	return hash;
}

// Remove an entry from the table given its hash value and its packet fields
struct sad_entry_egress * sad_egress::remove_entry(struct pkt_fields * check_fields, uint32_t hash)
{
	if(check_fields == NULL)
		return NULL;
	uint32_t index = hash % SAD_MAX_EGRESS;
	struct sad_entry_egress * iterator = sad_table_egress[index], * pre_iterator = NULL;

	while (iterator != NULL){
		if(hash == iterator->hash && ! memcmp( check_fields, &iterator->_pkt_fields, sizeof(struct pkt_fields) ) )
			break;
		pre_iterator = iterator;
		iterator = iterator->next_entry;
	}
	if(iterator == NULL)
		return NULL;
	else if(pre_iterator == NULL){
		sad_table_egress[index] = iterator->next_entry;
		return iterator;
	}
	pre_iterator->next_entry = iterator->next_entry;

	return iterator;
}

// Add entry at the front of its list in the table
bool sad_egress::add_entry(struct sad_entry_egress * entry)
{
	if(hash_funct == NULL || entry == NULL)
		return false;

	uint32_t hash;

	hash = hash_fields( &entry->_pkt_fields );

	entry->hash = hash;

	uint32_t index = hash % SAD_MAX_EGRESS;
	entry->next_entry = sad_table_egress[index];
	sad_table_egress[index] = entry;

	return true;
}

// Get the corresponding policy content for a given set of packet fields
struct sad_entry_egress * sad_egress::get_policy_content(struct pkt_fields * check_fields)
{
	if(check_fields == NULL)
		return NULL;
	uint32_t hash;

	hash = hash_fields( check_fields );

	uint32_t index = hash % SAD_MAX_EGRESS;
	struct sad_entry_egress * iterator = sad_table_egress[index];
	while (iterator != NULL){
		if(iterator->hash == hash && ! memcmp(check_fields, &iterator->_pkt_fields, sizeof(struct pkt_fields) ) )
			return iterator;
		iterator = iterator->next_entry;
	}

	return NULL;
}

// Verify the existence of an entry with check_fields at its core
uint32_t sad_egress::policy_check(struct pkt_fields * check_fields)
{
	if(! check_fields )
		return false;
	struct sad_entry_egress * sad_entry = get_policy_content(check_fields);
	if( sad_entry )
		return sad_entry->spi;
	return 0;
}

// Set the hash function to be used with hash_fields;
void sad_egress::set_hash(uint32_t (*funct)(struct pkt_fields * fields)){
	hash_funct = funct;
}

// Use the hash function set with the method above
uint32_t sad_egress::hash_fields(struct pkt_fields * fields){
	return (*hash_funct)(fields);
}

// Obtain new sequence number to stamp on outgoing packet;
uint32_t sad_egress::get_new_seq_num(struct sad_entry_egress * entry)
{
	if(entry == NULL)
		return 0;
	uint32_t new_seq_num = odp_atomic_fetch_inc_u32(&entry->seq_cnt);
	new_seq_num ++;

	return (uint32_t)(new_seq_num);
}

// Set table entry pointers and function pointer to NULL
sad_egress::sad_egress()
{
	hash_funct = NULL;
	memset(	sad_table_egress, 0, sizeof(sad_table_egress) );
}

// Remove entry with given SPI
struct sad_entry_ingress * sad_ingress::remove_entry(uint32_t spi)
{
	if(spi >= SAD_MAX_INGRESS || spi < 256 || ((sad_table_ingress[spi].version & 1) == 0) )
		return NULL;
	sad_table_ingress[spi].version++;

	return &sad_table_ingress[spi];
}

// Add entry; assign it an SPI; return the SPI
uint32_t sad_ingress::add_entry(struct sad_entry_ingress * entry)
{
	if(entry == NULL)
		return 0;
	uint32_t spi = get_new_spi();
	if(spi){
		uint16_t version = sad_table_ingress[spi].version + 1;
		memcpy( &sad_table_ingress[spi], entry, sizeof(struct sad_entry_ingress) );
		sad_table_ingress[spi].version = version;
		sad_table_ingress[spi].spi = spi;
	}

	return spi;
}

// Get entry for given SPI; NULL if SPI is not consistent or entry doesn't exist
struct sad_entry_ingress * sad_ingress::get_policy_content(uint32_t spi)
{
	if(spi >= SAD_MAX_INGRESS || spi < 256 )
		return NULL;
	return &sad_table_ingress[spi];
}

// Get new SPI from stack for a new SA
uint32_t sad_ingress::get_new_spi()
{
	if(spi_stack.empty())
		return 0; //include an error message in module in case SPI is 0 - NOT TO BE USED

	uint32_t spi = spi_stack.top();  //preview top
	spi_stack.pop(); //pop top
	return spi;
}


// Set pointers to NULL, fill SPI stack
sad_ingress::sad_ingress(bool * ready_flag)
{
	if(!ready_flag)
		*ready_flag = false;
	memset(sad_table_ingress, 0, sizeof(sad_table_ingress) );
	for(uint32_t i = 256; i < SAD_MAX_INGRESS; i++) {
		spi_stack.push(i);
	}

	if(!ready_flag)
		*ready_flag = true;
}

sad_ingress::~sad_ingress(){
}
