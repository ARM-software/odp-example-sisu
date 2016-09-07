/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

//The PPP packet descriptor and associated definitions

#ifndef _PPP_BUFFER_H
#define _PPP_BUFFER_H

#include <stddef.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef SISU_DEBUG
	#include <list>
	#include <string>
	#include "../instr/debug.h"
#endif
#include "odp.h"
#include "stdatomic.h"
#include "compiler.h"
#include "pkt_hdrs.h"
#ifdef ACCOUNTING
#include "timestamp.h"
#endif

class ppp_graph;
class ppp_route;

//Type of link layer address
enum pb_lladdr
{
    PPP_LLADDR_THISHOST  = 0,
    PPP_LLADDR_OTHERHOST = 1,
    PPP_LLADDR_MULTICAST = 2,
    PPP_LLADDR_BROADCAST = 3,
    PPP_LLADDR_MASK      = 3//Mask of all used bits
};

//Type of framing
enum ppp_framing
{
    PPP_FRAMING_NONE     = 0,//Must assume ppp_packet.protocol() is valid
    PPP_FRAMING_ETHERNET = 4,
    PPP_FRAMING_MASK     = 4//Mask of all used bits
};

class ppp_packet
{
#ifdef SISU_DEBUG
	std::list<std::string> *_log;
	bool discarded;
#endif
    //PPP data stored in ODP packet headroom/metadata
    odp_queue_t _queue;//ODP queue packet came from
    ppp_packet *_nextpkt;//Pointer to next packet/segment (e.g. for reassembly)
    ppp_route *_route;//Cached route lookup
    void *_context;//User defined context
    void *_spareptr;//Spare pointer used by some modules for housekeeping
#ifdef ACCOUNTING
    uint64_t _cycles;//Acculumated cycles spent processing this pkt
#endif
    int32_t _ifx;//Ingress/egress interface (TODO use odp_packet_input()?)
    uint16_t _proto;//Protocol of next unconsumed header
    uint8_t _hdrsz;//Amount of headers currently consumed
    uint8_t _parser;//Parser flags (e.g. lladdr, framing)

public:
    odp_packet_t _pkth;//ODP packet handle
    //Currently only used by IP reassembly code
    uint32_t temp;

#ifdef SISU_DEBUG
	inline void log_alloc()
	{
		_log = new std::list<std::string>;
		discarded = false;
	}

	inline void log_add(std::string msg)
	{
		_log->push_back(msg);
	}

	inline void log_set_discarded()
	{
		discarded = true;
	}

	inline void log_print()
	{
		std::list<std::string>::iterator log_it;
		log_it = _log->begin();

		if (log_it != _log->end() &&
		    ((only_discarded && discarded) || (!only_discarded))) {
			printf("\n*** Packet lifetime report ***\n");
			printf("------------------------------\n");
			for (log_it = _log->begin();
			      log_it != _log->end();
			      ++log_it) {
				printf("%s\n", (*log_it).c_str());
			}
			printf("------------------------------\n");
		}
	}
#endif

    inline void init(odp_packet_t ph, odp_queue_t qh)
    {
	//Subroutine calls first
	odp_packet_user_ptr_set(ph, this);
	_pkth = ph;
	_queue = qh;
	_route = NULL;
	_nextpkt = NULL;
	_spareptr = NULL;
#ifdef ACCOUNTING
	//_cycles = 0;
#endif
	_ifx = 0;
	_hdrsz = 0;
	_proto = 0;
	_parser = 0;//Populate from ODP
	temp = 0;
	//Caller might perform more initializations after we have returned,
	//allow optimizations by not calling any subroutines here
    }

    //Available headroom before data
    inline uint32_t headroom() const
    {
	//Subtract the area we use
	assert(odp_packet_headroom(_pkth) >= sizeof(ppp_packet));
	return odp_packet_headroom(_pkth) - sizeof(ppp_packet);
    }
    //Size of data in first segment
    inline uint32_t seglen() const
    {
	return odp_packet_seg_len(_pkth);
    }

    //Size of headers parsed so far
    inline void hdrsize_set(uint32_t h)
    {
	_hdrsz = h;
    }
    inline void hdrsize_add(uint32_t h)
    {
	_hdrsz += h;
    }
    inline uint32_t hdrsize() const
    {
	return _hdrsz;
    }

    //Protocol at hdrsize, e.g. IPv4
    inline void protocol_set(uint32_t p)
    {
	_proto = p;
    }
    inline uint32_t protocol() const
    {
	return _proto;
    }

    //Parser results
    inline void parserflags_set(uint32_t f)
    {
	_parser = f;
    }
    inline uint32_t parserflags() const
    {
	return _parser;
    }
    //Access link layer address portion of parser flags
    inline void lladdr_set(enum pb_lladdr lladdr)
    {
	//Don't change other bits
	parserflags_set((parserflags() & ~PPP_LLADDR_MASK) |
		(lladdr & PPP_LLADDR_MASK));
    }
    inline enum pb_lladdr lladdr() const
    {
	return (enum pb_lladdr)(parserflags() & PPP_LLADDR_MASK);
    }
    //Access framing portion of parser flags
    inline enum ppp_framing framing() const
    {
	return (enum ppp_framing)(parserflags() & PPP_FRAMING_MASK);
    }
    inline void framing_set(enum ppp_framing f)
    {
	//Don't change other bits
	parserflags_set((parserflags() & ~PPP_FRAMING_MASK) |
		(f & PPP_FRAMING_MASK));
    }

    inline void ifindex_set(int32_t i)
    {
	_ifx = i;
    }
    inline int32_t ifindex() const
    {
	return _ifx;
    }

    inline void context_set(void *p)
    {
	_context = p;
    }
    inline void *context() const
    {
	return _context;
    }
    inline void context_skip(uint32_t sz)
    {
	_context = static_cast<char*>(_context) + sz;
    }

    //Reassembly support
    inline void nextpkt_set(ppp_packet *p)
    {
	_nextpkt = p;
    }
    inline ppp_packet *nextpkt() const
    {
	return _nextpkt;
    }

    //Spare pointer used by some modules (e.g. embif/capif to link packets)
    inline void spareptr_set(void *p)
    {
	_spareptr = p;
    }
    inline void *spareptr() const
    {
	return _spareptr;
    }

    inline void route_set(ppp_route *rt)
    {
	_route = rt;
    }
    inline ppp_route *route() const
    {
	return _route;
    }

    inline void ipv4_good_set(bool b)
    {
	odp_packet_has_ipv4_set(_pkth, (int)b);
    }
    inline bool ipv4_good() const
    {
	return odp_packet_has_ipv4(_pkth);//Assume IP header checksum is OK
    }
    inline bool udp_good() const
    {
	return odp_packet_has_udp(_pkth);//Assume UDP checksum OK
    }

    //Return pointer to start of packet data buffer
    inline void *data_ptr() const
    {
	return odp_packet_data(_pkth);
    }
    //Return pointer to next unparsed data in packet
    inline void *payload_ptr() const
    {
	return (char *)odp_packet_data(_pkth) + hdrsize();
    }

    //Compute total length of (a potentially segmented) packet
    inline uint32_t length() const
    {
	uint32_t len = 0;
	const ppp_packet *pkt = this;
	do
	{
	    len += odp_packet_len(pkt->_pkth);
	    pkt = pkt->nextpkt();
	} while (pkt != NULL);
	return len;
    }

    //Trim start of packet
    inline void trim_head(uint32_t sz)
    {
	assert(sz <= seglen());
	odp_packet_pull_head(_pkth, sz);
    }
    //Trim parsed headers
    inline void trim_head()
    {
	trim_head(hdrsize());
	hdrsize_set(0);
    }
    //Trim end of packet
    inline void trim_tail(uint32_t sz)
    {
	odp_packet_pull_tail(_pkth, sz);
    }

    //Make place for header in front of current data
    inline void *grow_head(uint32_t sz)
    {
	void *p = odp_packet_push_head(_pkth, sz);
	if (unlikely(p == NULL))
	    perror("odp_packet_push_head"), exit(-1);
	return p;
    }
    //Add data at end of packet
    inline void add_tail(const void *src, uint32_t len)
    {
	assert(odp_packet_head(_pkth) == this);
	assert(odp_packet_data(_pkth) >= (char *)this + sizeof(ppp_packet));
	int offset = this->length();//TODO
	void *rp = odp_packet_push_tail(_pkth, len);
	if (rp == NULL)
	    perror("odp_packet_push_tail"), abort();
	int rc = odp_packet_copy_from_mem(_pkth, offset, len, src);
	if (rc < 0)
	    perror("odp_packet_copydata_in"), exit(-1);
    }

    //Return pointer to IPv4 header in payload
    inline const ipv4hdr *get_ipv4hdr() const
    {
	assert(_proto == PPP_FRAMETYPE_IPV4);
	return static_cast<const ipv4hdr *>(payload_ptr());
    }
    //Return pointer to IPv4 header in payload
    inline ipv4hdr *get_ipv4hdr()
    {
	assert(_proto == PPP_FRAMETYPE_IPV4);
	return static_cast<ipv4hdr *>(payload_ptr());
    }

    //Return ODP queue handle where packet came from
    odp_queue_t queue() const
    {
	return _queue;
    }

    //Set ODP queue handle where packet should be enqueued to
    void queue_set(odp_queue_t queue)
    {
	_queue = queue;
    }

    //Begin cycle accounting for this packet
    inline void cycles_begin()
    {
#ifdef ACCOUNTING
	//Verify that we haven't missed any end() call
	assert((_cycles & 1) == 0);
	//Update cycle count
	_cycles = read_ccnt() << 1;
	//Mark cycle counting in progress
	_cycles |= 1;
#endif
    }
    //End cycle accounting for this packet
    inline void cycles_end()
    {
#ifdef ACCOUNTING
	//Verify that we haven't missed any begin() call
	assert((_cycles & 1) != 0);
	//Mark cycle count not in progress
	_cycles ^= 1;
	//Update cycle count (needs to be last!)
	_cycles = (read_ccnt() << 1) - _cycles;
#endif
    }
    inline uint64_t cycles() const
    {
#ifdef ACCOUNTING
	if ((_cycles & 1) == 0)
	    return _cycles >> 1;
	else
	    return 0;
#else
	return 0;
#endif
    }
    inline bool is_counting()
    {
#ifdef ACCOUNTING
	return (_cycles & 1) != 0;
#else
	return true;
#endif
    }

    //TX: Compute IPv4 header checksum
    inline void tx_ipv4_csum_set()
    {
	//TODO
    }
    inline bool tx_ipv4_csum() const
    {
	return true;//TODO
    }
    //TX: Use link layer broadcast address
    inline void tx_brdcst_addr_set()
    {
	//TODO
    }
    inline bool tx_brdcst_addr() const
    {
	return false;//TODO
    }

    void dump(ppp_graph *, uint32_t flags) const;

    //Assume exclusive ownership of packet
    //Reference counting not supported by ODP so a no-op
    inline ppp_packet *exclusive()
    {
	return this;
    }

    static void operator delete(void *p)
    {
	//delete should not be called as this won't support reference counting
	abort();
    }
    inline void free()
    {
#ifdef SISU_DEBUG
		log_print();
		delete _log;
#endif
	odp_packet_free(_pkth);
    }
    inline void enqueue(odp_queue_t q)
    {
	odp_queue_enq(q, odp_packet_to_event(_pkth));
    }

    inline odp_packet_t get_odp_pkt()
    {
	return _pkth;
    }

    inline void *get_tail_pointer()
    {
	return odp_packet_tail(_pkth);
    }

};


//Bit flags for dump() function
#define PPP_DUMP_BUFFER	0x0001
#define PPP_DUMP_RAWDUMP       0x0002
#define PPP_DUMP_L2HDR	 0x0004
#define PPP_DUMP_ARP	   0x0008
#define PPP_DUMP_IPHDR	 0x0010
#define PPP_DUMP_IPL4HDR       0x0020
#define PPP_DUMP_IPL4DATA      0x0040

#endif /* _PPP_BUFFER_H */
