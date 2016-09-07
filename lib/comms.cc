/* Copyright 2016, ARM Limited or its affiliates. All rights reserved. */

#include "comms.h"

#define CP_MSG_PREAMBLE		0x71f609e0

comms::comms(uint16_t local_port, bool wait_for_handshake)
{
	_n_addresses = 0;

	// Create UDP socket
	if ((_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Cannot create socket");
		exit(0);
	}

	// Bind socket
	struct sockaddr_in myaddr;
	memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(local_port);

	if (bind(_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		perror("bind failed");
		exit(0);
	}

	printf("Socket bound.\n");

	if (wait_for_handshake) {
		struct cp_msg *msg;
		struct sockaddr_in remaddr;

		printf("Waiting for handshake.\n");

		do {
			msg = wait_for_message(&remaddr);
		} while (msg->hdr.type != CP_MSG_HANDSHAKE);

		peer_id_t peer = add_peer(inet_ntoa(remaddr.sin_addr));

		struct cp_msg reply;
		reply.hdr.type = CP_MSG_HANDSHAKE;

		send_message(peer, &reply);
		printf("Sent handshake message.\n");
	}
}

struct cp_msg * comms::wait_for_message(struct sockaddr_in *sender_addr)
{
	// Prepare socket for reception
	struct sockaddr_in remaddr;
	socklen_t addrlen = sizeof(remaddr);

	// Enter infinite loop
	printf("Waiting for message.\n");
	while (1) {
		struct cp_msg_hdr *hdr = (struct cp_msg_hdr *)_buf;
		ssize_t recvlen = recvfrom(_fd, _buf, sizeof(_buf), 0, (struct sockaddr *)&remaddr, &addrlen);
		if ((recvlen < (ssize_t)sizeof(struct cp_msg_hdr)) || (hdr->preamble != CP_MSG_PREAMBLE)) {
			printf("Incorrect msg received.\n");
			continue;
		}

		if (sender_addr != NULL)
			memcpy(sender_addr, &remaddr, addrlen);

		return (struct cp_msg *)_buf;
	}
}

void comms::send_message(peer_id_t dst_id, struct cp_msg *msg)
{
	msg->hdr.preamble = CP_MSG_PREAMBLE;
	if (sendto(_fd, msg, sizeof(struct cp_msg), 0, (struct sockaddr *)&addr_list[dst_id], sizeof(struct sockaddr)) < 0) {
		perror("sendto failed");
		exit(0);
	}
}

peer_id_t comms::add_peer(char *ip_addr)
{
	struct sockaddr_in *destaddr = &addr_list[_n_addresses];

	memset((char*)destaddr, 0, sizeof(struct sockaddr_in));
	destaddr->sin_family = AF_INET;
	destaddr->sin_port = htons(COMMS_PORT);

	inet_aton(ip_addr, &(destaddr->sin_addr));
	printf("Peer added with IP %s.\n", ip_addr);

	return _n_addresses++;
}

comms::~comms()
{
	close(_fd);
	printf("Socket destroyed.\n");
}
