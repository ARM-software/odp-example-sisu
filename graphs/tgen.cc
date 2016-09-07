/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in.h>

#include "../instr/accounting.h"
#include "../instr/debug.h"

#include "../ppp/ppp_packet.h"
#include "../ppp/ppp_pktpool.h"
#include "../ppp/pkt_hdrs.h"
#include "../ppp/ppp_graph.h"

#include "tgen.h"

#define IPV4_VERS_HLEN 0x45
#define IPV4_DEF_TTL 64
#define IPV4_TOS 0x00
#define IPV4_SRC_ADDR 0x11111111
#define IPV4_DST_ADDR 0x11111111
#define UDP_PORT 0

#define PKT_SIZE 0
#define PAYLOAD_SIZE 540

#define NS_IN_MS 1000000

const char *payload = "kdijshfliuhsdfgliuhsdflgiushdfgilusdfh" \
					   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
						   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
							   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
								   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
									   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
										   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
											   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
												   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
													   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
														   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
															   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																	   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																		   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																			   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																				   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																					   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																						   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																							   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																								   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																									   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																										   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																											   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																												   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																													   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																														   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																															   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																	   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																		   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																			   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																				   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																					   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																						   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																							   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																								   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
																																									   "sdijfksdijfksjhdfksjhdfkgliudfhgdfsdfg" \
					   "sdihjfkdhsfksfliuharliguhsegilruhsei";

void tgen::stop()
{
	_tgen_if->_stop = true;
}

void tgen::start_flow(bearer_context *ctx)
{
	odp_rwlock_write_lock(&(_tgen_if->rwlock));
	_tgen_if->_ctx_list.push_back(ctx);
	odp_rwlock_write_unlock(&(_tgen_if->rwlock));
}

void tgen::stop_flow(bearer_context *ctx)
{
	odp_rwlock_write_lock(&(_tgen_if->rwlock));
	if (*(_tgen_if->_ctx_it) == ctx)
		_tgen_if->_ctx_it++;

	std::list<bearer_context *>::iterator it;
	for (it = _tgen_if->_ctx_list.begin(); it != _tgen_if->_ctx_list.end(); it++) {
		if (*it == ctx) {
			_tgen_if->_ctx_list.erase(it);
			break;
		}
	}
	odp_rwlock_write_unlock(&(_tgen_if->rwlock));
}

tgen::tgen(const char *name, ppp_pktpool *pktpool) : ppp_graph(name, 5)
{
	_sink = new odp_sink(this, "sink");
	_tgen_if = new tgen_if(this, "gen", 1, pktpool);
	_tgen_if->ipv4good.attach(&(_sink->input));
	_tgen_if->deliver.attach(&(_sink->input));
}

tgen::~tgen()
{
	delete _sink;
	delete _tgen_if;
}

void tgen_if::transmit_pkt(ppp_packet *pkt)
{
	uint32_t pktlen;
	pktlen = pkt->length();
	stats.tx.pkts.add(1);
	stats.tx.bytes.add(pktlen);
	pkt->cycles_end();

	pkt->free();
}

void tgen_if::traverse_outputs(void (*apply)(void *h, ppp_module *f, ppp_output *p), void *handle)
{
	ppp_if::traverse_outputs(apply, handle);
}

void tgen_if::sd_handler(int sd, int poll_events)
{
	while (!_stop) {
		ACCOUNTING_BEGIN();
		ppp_packet *pkt = pool->alloc_pkt(PKT_SIZE, ODP_QUEUE_INVALID);

		if (unlikely(pkt == NULL)) {
				continue;
		}
		ACCOUNTING_END(TGEN_PACKET_ALLOCATION);

		DEBUG_PKT("Allocated");

		ACCOUNTING_BEGIN();

		// Set bearer context and queue
		odp_rwlock_read_lock(&rwlock);
		if (_ctx_list.empty()) {
			odp_rwlock_read_unlock(&rwlock);
			pkt->free();
			continue;
		}

		pkt->add_tail(payload, PAYLOAD_SIZE);

		if (_ctx_it == _ctx_list.end())
			_ctx_it = _ctx_list.begin();
		struct bearer_context *ctx = static_cast<struct bearer_context *>(*_ctx_it);
		_ctx_it++;
		odp_rwlock_read_unlock(&rwlock);

		pkt->context_set(ctx);
		pkt->queue_set(((struct tgen_bearer_context *)ctx)->queue);
		pkt->context_skip(sizeof(struct tgen_bearer_context));

		// Add UDP header
		struct udphdr *udp_hdr = static_cast<struct udphdr *>(pkt->grow_head(sizeof(struct udphdr)));
		udp_hdr->src_port = udp_hdr->dst_port = UDP_PORT;
		udp_hdr->length = htons(pkt->length());
		udp_hdr->chksum = 0; // UDP checksum is optional

		// Add IP header
		struct ipv4hdr *ipv4_hdr = static_cast<struct ipv4hdr *>(pkt->grow_head(sizeof(struct ipv4hdr)));
		ipv4_hdr->vers_hlen = IPV4_VERS_HLEN;
		ipv4_hdr->tos = 0;
		ipv4_hdr->total_len = htons(pkt->length());
		ipv4_hdr->id = 0;
		ipv4_hdr->fraginfo = 0;
		ipv4_hdr->ttl = IPV4_DEF_TTL;
		ipv4_hdr->ip_proto = PPP_IPPROTO_UDP;
		ipv4_hdr->src_addr = IPV4_SRC_ADDR;
		ipv4_hdr->dst_addr = IPV4_DST_ADDR;
		ipv4_hdr->hchecksum = 0;
		ipv4_hdr->hchecksum = ipv4_hdr->checksum();
		ACCOUNTING_END(TGEN_PACKET_GENERATION);

		ppp_if::input_raw_pkt(pkt);
	}

	unregister_sd(sd);
	close(sd);
}

tgen_if::tgen_if(ppp_graph *_graph,
		   const char *_name,
		   ppp_ifindex_t _ifx,
		   ppp_pktpool *_pktpool) :
		   ppp_if(_graph, _name, _ifx, (ppp_edgeP_f)&tgen_if::transmit_pkt),
		   pool(_pktpool)
{
	_stop = false;

	sd = open("/dev/null", O_RDONLY);
	if (sd == -1)
		perror("open"), abort();

	_ctx_it = _ctx_list.begin();
	odp_rwlock_init(&rwlock);

	register_sd(sd, POLLIN);
}

tgen_if::~tgen_if()
{
	close(sd);
}
