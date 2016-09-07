/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#define DLT_RAW2 101 //Sometimes this value is used for DLT_RAW
#include <netinet/in.h>

#include "ppp_packet.h"
#include "ppp_pktpool.h"
#include "pkt_hdrs.h"

#include "capif.h"

void
capif::transmit_pkt(ppp_packet *pkt)
{
    uint32_t pktlen;
    pktlen = pkt->length();
    stats.tx.pkts.add(1);
    stats.tx.bytes.add(pktlen);
    pkt->cycles_end();
    if (pd != NULL)
    {
	struct pcap_pkthdr pkt_hdr;
	gettimeofday(&pkt_hdr.ts, NULL);
	//TODO scatter-gather support
	//No scatter/gather support so only write first segment
	pkt_hdr.caplen = pkt->seglen();//Captured size == first segment
	pkt_hdr.len = pktlen;//Total size
	odp_ticketlock_lock( &lock );
	pcap_dump((u_char *)pd, &pkt_hdr, (const u_char*)pkt->data_ptr());
	odp_ticketlock_unlock( &lock );
    }
	if (loopback) {
		ipv4good.enter(pkt);
	} else {
 	   pkt->free();
	}
}

capif::capif(ppp_graph *_graph,
	     const char *_name,
	     ppp_ifindex_t _ifx,
	     ppp_pktpool *_pktpool,
	     const char *pcap_input,
	     const char *pcap_output,
			 uint32_t linktype,
			 bool lb) :
    ppp_if(_graph, _name, _ifx, (ppp_edgeP_f)&capif::transmit_pkt),
    pool(_pktpool),
	tx_linktype(linktype),
	loopback(lb)
{
    //Assume Ethernet interface, input pcap file may override
    iftype = PPP_IFTYPE_ETHERNET;
    llhdrsize = 14;
    mtu = 1500;
    admstate = 1;
    discard_inb = false;
    fp = NULL;
    pf = NULL;
    pd = NULL;
    memset(remote_ip, 0, sizeof remote_ip);
    num_remote = 0;
    linktype = DLT_EN10MB;
    if (pcap_input != NULL)
    {
	char errbuf[PCAP_ERRBUF_SIZE];
	fp = fopen(pcap_input, "r");
	if (fp == NULL)
	{
	    fprintf(stderr, "%s: Failed to open, error %s\n",
		    pcap_input, strerror(errno));
	    ::exit(EXIT_FAILURE);
	}
	pf = pcap_fopen_offline(fp, errbuf);
	if (pf == NULL)
	    perror("pcap_fopen_offline"), abort();
	linktype = pcap_datalink(pf);
	if (linktype != DLT_EN10MB && linktype != DLT_RAW &&
	    linktype != DLT_RAW2)
	{
	    fprintf(stderr, "%s: Unsupported linktype %d\n",
		    pcap_input, linktype);
	    ::exit(EXIT_FAILURE);
	}
	if (linktype != DLT_EN10MB)//linktype == DLT_RAW/DLT_RAW2
	{
	    //Override defaults
	    iftype = PPP_IFTYPE_IPTUNNEL;
	    llhdrsize = 0;
	}
	//Else default values OK for Ethernet
	register_sd(fileno(fp), POLLIN);
    }
    if (pcap_output != NULL)
    {
	pcap_t *p;
	p = pcap_open_dead(tx_linktype, 0xFFFF);
	if (p == NULL)
	    perror("pcap_open_dead"), abort();

	pd = pcap_dump_open(p, pcap_output);
	if (pd == NULL)
	{
	    fprintf(stderr, "%s: Failed to open, error %s\n",
		    pcap_output, strerror(errno));
	    ::exit(EXIT_FAILURE);
	}
//	pcap_close(p);
    }
}

capif::~capif()
{
    if (fp != NULL)
    {
	unregister_sd(fileno(fp));
	if (pf != NULL)
	    pcap_close(pf);
//	fclose(fp);//Performed by pcap_close?
    }
    if (pd != NULL)
	pcap_dump_close(pd);
}

void capif::set_promiscuous(bool enable)
{
    ppp_if::set_promiscuous(enable);
}

void capif::discard_inbound(bool enable)
{
    discard_inb = enable;
}

void capif::traverse_outputs(void (*apply)(void *h, ppp_module *f, ppp_output *p), void *handle)
{
    ppp_if::traverse_outputs(apply, handle);
}

void capif::sd_handler(int sd, int poll_events)
{
    (void)sd;
    (void)poll_events;

    for (;;)
    {
//next_pkt:
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;

	int st = pcap_next_ex(pf, &pkt_hdr, &pkt_data);
	if (st < 0)
	{
	    unregister_sd(fileno(fp));
	    if (pf != NULL)
		pcap_close(pf);//Also fcloses associated fp
	    fp = NULL;
	    pf = NULL;
	    break;
	}
	ppp_packet *pkt = pool->alloc_pkt(pkt_hdr->caplen, ODP_QUEUE_INVALID);
	if (unlikely(pkt == NULL))
	    perror("pool->alloc_pkt()"), abort();
	pkt->add_tail(pkt_data, pkt_hdr->caplen);

	pkt->ifindex_set(ifx);

	if (linktype == DLT_EN10MB)
	{
	    if (likely(pkt_hdr->caplen >= sizeof(struct ethhdr)))
	    {
		pkt->hdrsize_set(sizeof(struct ethhdr));
		pkt->parserflags_set(PPP_FRAMING_ETHERNET);//Set by input_eth_pkt()
		const ethhdr *eth = static_cast<const ethhdr *>(pkt->data_ptr());
		if (unlikely(ntohs(eth->frametype) < 0x600))
		{
		    pkt->protocol_set(PPP_FRAMETYPE_NOTDIX);
		}
		else
		{
		    pkt->protocol_set(ntohs(eth->frametype));
		}

		//Simulate a little bit of HW acceleration
		if (likely(pkt->protocol() == PPP_FRAMETYPE_IPV4))
		{
		    ppp_if::verify_ipv4_csum(pkt);
		}

		pkt->cycles_begin();
		ppp_if::input_eth_pkt(pkt);
	    }
	    //Else runt packet ignored
	}
	else//linktype == DLT_RAW/DLT_RAW2
	{
	    pkt->hdrsize_set(0);
	    pkt->parserflags_set(PPP_FRAMING_NONE | PPP_LLADDR_THISHOST);
	    pkt->protocol_set(PPP_FRAMETYPE_IPV4);
	    ppp_if::verify_ipv4_csum(pkt);
	    pkt->cycles_begin();
	    ppp_if::input_raw_pkt(pkt);
	}
    }
}
