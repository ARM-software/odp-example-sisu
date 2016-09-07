/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

// Packet Processing Pipeline - input/output definitions

#ifndef _PPP_INOUT_H
#define _PPP_INOUT_H

#include <stdint.h>
#include "compiler.h"
#ifdef ACCOUNTING
#include "ppp_packet.h"
#endif
#include <odp.h>

//Opaque data types
class ppp_module; //packet & protocol processing module
class ppp_packet; //packet descriptor

//ppp_edgeP_f - the basic packet connection
typedef void (ppp_module::*ppp_edgeP_f)(ppp_packet *pkt);

typedef uint32_t ppp_properties;
#define PROP_SINGLEPKT (1U << 0) //Single packet (pkt->nextpkt == NULL)
#define PROP_CONTEXT   (1U << 1) //Has context ptr (pkt->hdr_context != NULL)
#define PROP_IPv4      (1U << 2) //pkt->payload_ptr() points to IPv4 header
#define PROP_IPv4GOOD  (1U << 3) //IPv4 header OK (checksum and total_len)
#define PROP_IPUNFRAG  (1U << 4) //Unfragmented/reassembled IP datagram

//Base class for inputs
class ppp_input
{
public:
    const char *const name;
    ppp_module *const parent;
    ppp_properties needs;

    ppp_input(const char *_name,
	      ppp_module *_parent,
	      ppp_properties _prop = 0) :
	name(_name),
	parent(_parent),
	needs(_prop)
    {
    }
};

//Base class for output
class ppp_output
{
public:
    const char *const name;
    const ppp_input *peer;
    ppp_module *module;//Module of peer input when attached
    ppp_module *const parent;//Always parent module
    ppp_properties grants;

    ppp_output(const char *_name,
	       ppp_module *_parent,
	       ppp_properties _prop = 0) :
	name(_name),
	peer(NULL),
	module(_parent),
	parent(_parent),
	grants(_prop)
    {
    }
    bool attached()
    {
	return peer != NULL;
    }
};

//Class for inputs with prototype (ppp_packet *)
class ppp_inputP : public ppp_input
{
public:
    const ppp_edgeP_f function;

    ppp_inputP(const char *_name,
	       ppp_module *_parent,
	       ppp_edgeP_f f,
	       ppp_properties _prop = 0) :
	ppp_input(_name, _parent, _prop),
	function(f)
    {
    }
};

//Class for outputs with prototype (ppp_packet *)
class ppp_outputP : public ppp_output
{
    ppp_edgeP_f function;
public:
    ppp_outputP(const char *_name,
		ppp_module *_parent,
		ppp_properties _prop = 0);

    //Attach this output to the input of another module
    void attach(ppp_inputP *input);

    //Pass a packet to the attached module
    inline void enter(ppp_packet *pkt)
    {
	((module)->*(function))(pkt);//Call to member function of module
    }
};

//Class for outputs with prototype (ppp_packet *)
class ppp_outputPv : public ppp_outputP
{
    char buf[12];
public:
    ppp_outputPv();
    void set(ppp_module *_parent,
	     const char *_name,
	     ppp_properties _prop = 0);
};

#endif //_PPP_INOUT_H
