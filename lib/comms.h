/* Copyright 2016, ARM Limited or its affiliates. All rights reserved. */

#ifndef _COMMS_H
#define _COMMS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "../agent/cpmessages.h"

#define COMMS_PORT				55555
#define BUFFER_LENGTH			1024
#define MAX_N_ADDRESSES			10

#define PEER_ADDR_INVALID		-1

typedef int peer_id_t;

class comms
{
	// Socket parameters
	int _fd;

	// Addresses
	int _n_addresses;
	struct sockaddr_in addr_list[MAX_N_ADDRESSES];

	// Receive buffer
	unsigned char _buf[BUFFER_LENGTH];

public:
	// Constructor/destructor
	comms(uint16_t local_port, bool wait_for_handshake = false);
	~comms();

	peer_id_t add_peer(char *ip_addr);
	struct cp_msg * wait_for_message(struct sockaddr_in *sender_addr = NULL);
	void send_message(peer_id_t dst_id, struct cp_msg *msg);
};

#endif //_COMMS_H
