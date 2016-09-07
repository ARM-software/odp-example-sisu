/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <stdint.h>
#include <cstddef>
#include "spd.h"
#include <assert.h>

bool spd::entry_check(struct spd_entry * entry, struct pkt_fields * check_fields)
{
	if( ! entry || ! check_fields)
		return false;

	// Check source IP addr ranges
	uint32_t mask = ~( (1 << entry->src_ip_range.mask_len) - 1 );
	if(entry->src_ip_range.mask_len == 32)
		mask = 0;

	if( ( entry->src_ip_range.base_ip & mask ) != (mask & check_fields->src_ip))
		return false;

	// Check destination IP ranges
	mask = ~( (1 << entry->dest_ip_range.mask_len) - 1 );
	if(entry->dest_ip_range.mask_len == 32)
		mask = 0;

	if( ( entry->dest_ip_range.base_ip & mask ) != (mask & check_fields->dest_ip))
		return false;

	// Check source port ranges
	if( (check_fields->src_port < entry->src_port_range.min_port) || (check_fields->src_port > entry->src_port_range.max_port) )
		return false;

	// Check destination port ranges
	if( (check_fields->dest_port < entry->dest_port_range.min_port) || (check_fields->dest_port > entry->dest_port_range.max_port) )
		return false;

	// Check next layer protocol
	if(entry->next_layer_proto != check_fields->next_layer_proto)
		return false;

	return true;
}

bool spd::add_entry(struct spd_entry * entry, uint16_t position)
{
	if(! entry)
		return false;

	// Check if entry can exist
	if(position > num_entries + 1 || position < 1)
		return false;

	if(position == 1){
		entry->next_entry = first_entry;
		first_entry = entry;
		num_entries++;
		return true;
	}

	uint32_t cnt = 1;
	struct spd_entry * front_iterator = first_entry;
	struct spd_entry * back_iterator = NULL;

	// Scroll to desired position
	while (cnt < position) {
		cnt++;
		back_iterator = front_iterator;
		front_iterator = front_iterator->next_entry;
	}

	// Insert entry in linked list
	entry->next_entry = front_iterator;

	if(back_iterator != NULL)
		back_iterator->next_entry = entry;

	num_entries++;

	return true;
}

// In the first position - highest priority
void spd::add_entry_front(struct spd_entry * entry)
{
	if(! entry)
		return;
	if(num_entries > 0)
		entry->next_entry = first_entry;
	first_entry = entry;
	num_entries++;
}

// Remove an entry given its index
struct spd_entry * spd::remove_entry(uint16_t position)
{
	// Check for inconsistencies
	if( position > 0 && position <= num_entries )
		return NULL;

	struct spd_entry * to_delete, * pre_iterator;
	to_delete = first_entry;
	pre_iterator = NULL;

	// If first, move first_entry down and return old one
	if (position == 1) {
		first_entry = first_entry->next_entry;
		return to_delete;
	}

	// Get to requested entry
	uint16_t cnt = 1;
	while (cnt < position){
		cnt++;
		pre_iterator = to_delete;
		to_delete = to_delete->next_entry;
	}

	// Decouple and return
	pre_iterator->next_entry = to_delete->next_entry;
	return to_delete;
}


// Decouples first entry and returns it
struct spd_entry * spd::remove_entry_front()
{
	struct spd_entry * to_delete = first_entry;

	if(first_entry != NULL)
		first_entry = first_entry->next_entry;

	return to_delete;
}

// Find first hit in SPD table
struct spd_entry *spd::get_policy(struct pkt_fields * check_fields)
{
	if(! check_fields)
		return NULL;
	struct spd_entry * iterator = first_entry;

	// Iterate SPD, searching for first hit
	while ( iterator != NULL && ! entry_check( iterator, check_fields ) ) {
		iterator = iterator->next_entry;
	}

	// Return hit
	return iterator;
}

// Get the first policy
struct spd_entry *spd::get_first_policy()
{
	return first_entry;
}

// Get number of entries in table
uint16_t spd::get_num_entries()
{
	return num_entries;
}

spd::spd()
{
	first_entry = NULL;
	num_entries = 0;
}

spd::~spd(){
}
