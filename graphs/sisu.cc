/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include "sisu.h"
#include "../instr/debug.h"

void sisu::stop()
{
	_src->stop();
}

uint32_t sisu::local_ip()
{
	return _ip->_local_ip;
}

const uint8_t *sisu::local_mac()
{
	return _eth->_local_mac;
}

queue_context *sisu::create_context(odp_queue_t queue)
{
	queue_context *ctx = new queue_context(_src, PPP_FRAMING_ETHERNET);
	_src->register_context(queue, ctx);

	return ctx;
}

void sisu::destroy_context(queue_context *ctx)
{
	delete ctx;
}

void sisu::add_ppp_route(ppp_route *route)
{
	_ip->add_ppp_route(route);
}

uint32_t sisu::create_teid(odp_queue_t queue)
{
	return _gtp->queue_table_add(queue);
}

void sisu::destroy_teid(uint32_t teid)
{
	_gtp->queue_table_del(teid);
}

#ifndef NO_IPSEC
struct sad_entry_egress *sisu::add_remote_sad_entry(struct egr_sa_init_fields * fields)
{
	return _ipsec->add_remote_sad_entry(fields);
}

struct sad_entry_ingress *sisu::add_local_sad_entry(struct ing_sa_init_fields * fields)
{
	return _ipsec->add_local_sad_entry(fields);
}

odp_crypto_session_params_t *sisu::remove_remote_sad_entry( struct sad_entry_egress *entry )
{
	return _ipsec->remove_remote_sad_entry( &entry->_pkt_fields );
}

void *sisu::remove_local_sad_entry( struct sad_entry_ingress *entry )
{
	return _ipsec->remove_local_sad_entry( entry->spi );
}

odp_crypto_session_params_t *sisu::destroy_local_sad_sessions( void *to_remove )
{
	return _ipsec->destroy_local_sad_sessions( to_remove );
}

bool sisu::remove_spd_entry(uint16_t position)
{
	return _ipsec->remove_spd_entry(position);
}

bool sisu::add_spd_entry(struct spd_init_fields *fields, uint16_t position)
{
	return _ipsec->add_spd_entry(fields, position);
}

uint32_t sisu::sad_entry_check(struct pkt_fields *check_fields)
{
	return _ipsec->sad_entry_check(check_fields);
}

void sisu::get_sa_handles(struct pkt_fields *check_fields, uint32_t spi, struct sa_handles *handles)
{
	handles->egress = _ipsec->get_egress_sa( check_fields );
	handles->ingress = _ipsec->get_ingress_sa( spi );
}

uint32_t sisu::get_num_sa_egr()
{
    return _ipsec->get_num_sa_egr();
}

uint32_t sisu::get_num_sa_ing()
{
    return _ipsec->get_num_sa_ing();
}

#endif

void sisu::attach_egress_input(odp_queue_t queue)
{
	if (_pcap_debug) {
		_src->output_pkt(queue)->attach(&(_cap0_egress->transmit));
	} else {
		_src->output_pkt(queue)->attach(&(_gtp->input_egress));
	}
}

void sisu::attach_egress_output(odp_pktio_t pktio_iface)
{
	_snk_egress->set_pktio_iface(pktio_iface);
}

void sisu::attach_ingress_input(odp_queue_t queue)
{
	if (_pcap_debug) {
		_src->output_pkt(queue)->attach(&(_cap0_ingress->transmit));
	} else {
		_src->output_pkt(queue)->attach(&(_eth->input_ingress));
	}
}

void sisu::execute()
{
	odp_atomic_fetch_inc_u32(&nthreads);

	// This will kick off odp_src, which in turn will poll the timeouts queue
	ppp_graph::execute();
	odp_atomic_fetch_dec_u32(&nthreads);
}

sisu::sisu(const char *name, uint32_t local_ip, const uint8_t *local_mac, bool pcap_debug) :
		   ppp_graph(name, 10), _pcap_debug(pcap_debug)
{
	_snk_egress = new odp_sink_pktio(this, "sink_egress");
	_snk_ingress = new odp_sink(this, "sink_ingress");

	_src = new odp_src(this, "src", true);
	_sync_ctrl_plane = 0;
	odp_atomic_init_u32(&_sync_data_plane, 0);
	odp_atomic_init_u32(&nthreads, 0);

	if (pcap_debug) {
		_cap0_egress = new capif(this, "egress input", 1, NULL, NULL, "egress_input.pcap", DLT_RAW, true);
		_cap0_egress->set_promiscuous(true);
		_cap1_egress = new capif(this, "egress output", 3, NULL, NULL, "egress_output.pcap", DLT_EN10MB, true);
		_cap1_egress->set_promiscuous(true);
#ifndef NO_IPSEC
		_cap2_egress = new capif(this, "egress before ipsec", 2, NULL, NULL, "egress_before_ipsec.pcap", DLT_RAW, true);
		_cap2_egress->set_promiscuous(true);
#endif
		_cap0_ingress = new capif(this, "ingress input", 4, NULL, NULL, "ingress_input.pcap", DLT_EN10MB, true);
		_cap0_ingress->set_promiscuous(true);
		_cap1_ingress = new capif(this, "ingress output", 6, NULL, NULL, "ingress_output.pcap", DLT_RAW, true);
		_cap1_ingress->set_promiscuous(true);
#ifndef NO_IPSEC
		_cap2_ingress = new capif(this, "ingress after ipsec", 5, NULL, NULL, "ingress_after_ipsec.pcap", DLT_RAW, true);
		_cap2_ingress->set_promiscuous(true);
#endif
	}

	_gtp = new gtpu(this, "gtpu");
	_ip = new ipv4(this, "ipv4", local_ip);
#ifndef NO_IPSEC
	_ipsec = new ipsec(this, "ipsec", local_ip);
#endif
	_eth = new ethernet(this, "ethernet", local_mac);

	if (pcap_debug) {
		_cap0_egress->ipv4good.attach(&(_gtp->input_egress));
	}

	_gtp->output_egress.attach(&_ip->input_egress);
#ifndef NO_IPSEC
	if (pcap_debug) {
		_ip->output_egress.attach(&(_cap2_egress->transmit));
		_cap2_egress->ipv4good.attach(&_ipsec->input_egress);
		_cap2_egress->deliver.attach(&_ipsec->input_egress);
	} else {
		_ip->output_egress.attach(&_ipsec->input_egress);
	}
	_ipsec->output_egress.attach(&_eth->input_egress);
#else
	_ip->output_egress.attach(&_eth->input_egress);
#endif

	if (pcap_debug) {
		_eth->output_egress.attach(&(_cap1_egress->transmit));
		_cap1_egress->ipv4good.attach(&(_snk_egress->input));
		_cap1_egress->deliver.attach(&(_snk_egress->input));
	} else {
		_eth->output_egress.attach(&(_snk_egress->input));
	}

	if (pcap_debug) {
		_cap0_ingress->ipv4good.attach(&(_eth->input_ingress));
		_cap0_ingress->deliver.attach(&(_eth->input_ingress));
	}

#ifndef NO_IPSEC
	_eth->output_ingress.attach(&_ipsec->input_ingress);
	if (pcap_debug) {
		_ipsec->output_ingress.attach(&(_cap2_ingress->transmit));
		_cap2_ingress->ipv4good.attach(&_ip->input_ingress);
		_cap2_ingress->deliver.attach(&_ip->input_ingress);
	} else {
		_ipsec->output_ingress.attach(&_ip->input_ingress);
	}
#else
	_eth->output_ingress.attach(&_ip->input_ingress);
#endif

	_ip->output_ingress.attach(&_gtp->input_ingress);

	if (pcap_debug) {
		_gtp->output_ingress.attach(&(_cap1_ingress->transmit));
		_cap1_ingress->ipv4good.attach(&(_snk_ingress->input));
		_cap1_ingress->deliver.attach(&(_snk_ingress->input));
	} else {
		_gtp->output_ingress.attach(&(_snk_ingress->input));
	}
}

sisu::~sisu()
{
	if (_pcap_debug) {
		delete _cap0_egress;
		delete _cap1_egress;
		delete _cap0_ingress;
		delete _cap1_ingress;
	}

	delete _gtp;
	delete _ip;
#ifndef NO_IPSEC
	delete _ipsec;
#endif
	delete _eth;
	delete _snk_egress;
	delete _snk_ingress;
	delete _src;
}
