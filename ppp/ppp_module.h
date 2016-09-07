/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

//Packet Processing Pipeline - module definitions

#ifndef _PPP_MODULE_H
#define _PPP_MODULE_H

#include <stdint.h>
#include <stdlib.h>
#include <odp.h>
#include "stdatomic.h"
#include "ppp_graph.h"

class ppp_packet;
class ppp_graph;
union ppp_message;

class ppp_module
{
    ppp_module *next;
protected:
    ppp_graph *graph;
public:
    const char * const name;
    const char * const type;
    atomic_uint32 num_discard_evt;

    ppp_module(ppp_graph *_gr, const char *_name, const char *_type);
    virtual ~ppp_module();
    ppp_module(const ppp_module & _mod)://Copy constructor
	name(NULL), type(NULL)
    {
	abort();
    }
    ppp_module &operator=(const ppp_module&)//Assignment operator
    {
	abort();
    }

    //Socket descriptor handler of module
    virtual void sd_handler(int sd, int poll_events);
    void register_sd(int sd, int poll_events);
    void unregister_sd(int sd);

    //The discard functions that are the default inputs for all outputs
    void discard_pkt(ppp_packet *pkt);
    void discard_pkt2(ppp_packet *pkt, uint32_t);
    void discard_evt(odp_event_t evt, void *ctx);

    friend class ppp_graph;
    friend class ppp_if;
};

#endif //_PPP_MODULE_H
