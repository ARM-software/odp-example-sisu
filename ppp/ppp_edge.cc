/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ppp_edge.h"
#include "ppp_module.h"

static const char *prop_str[] =
{
    "SINGLESEG",
    "CONTEXT",
    "IPv4",
    "IPv4GOOD",
    "IPUNFRAG",
    NULL //Terminate array
};


static char *prop2str(ppp_properties prop)
{
    size_t len = 0;
    for (unsigned i = 0; prop_str[i] != NULL; i++)
    {
	if ((prop & (1U << i)) != 0)
	{
	    len += strlen(prop_str[i]) + 1;
	}
    }
    char *str = new char[len + 1];
    str[0] = '\0';
    for (unsigned i = 0; prop_str[i] != NULL; i++)
    {
	if ((prop & (1U << i)) != 0)
	{
	    strcat(str, prop_str[i]);
	    strcat(str, ":");
	}
    }
    assert(str[len - 1] == ':');
    assert(strlen(str) == len);
    str[len - 1] = '\0';
    return str;
}

ppp_outputP::ppp_outputP(const char *_name, ppp_module *_parent, ppp_properties _prop) :
    ppp_output(_name, _parent, _prop),
    function(&ppp_module::discard_pkt)
{
}

void ppp_outputP::attach(ppp_inputP *input)
{
    if (unlikely(attached()))
    {
	//Output already attached
	fprintf(stderr, "Failed to attach %s.%s to %s.%s: "
			"already attached (to %s.%s)\n",
			parent->name, name, input->parent->name, input->name,
			peer->parent->name, peer->name);
	::exit(EXIT_FAILURE);
    }
#if 0
printf("attach %s.%s(%x) to %s.%s(%x)\n",
parent->name, name, grants,
input->parent->name, input->name, input->needs);
#endif
    ppp_properties missing = input->needs & ~grants;
    if (unlikely(missing != 0))
    {
	char *str = prop2str(missing);
	fprintf(stderr, "Failed to attach %s.%s to %s.%s: "
			"missing properties %s\n",
			parent->name, name, input->parent->name, input->name,
			str);
	::exit(EXIT_FAILURE);
    }
    peer = input;
    module = input->parent;
    function = input->function;
}

//Parameter-less constructor for arrays
ppp_outputPv::ppp_outputPv() :
    ppp_outputP(buf, NULL)
{
    //module and parent now NULL, not good.
    //Should be set later by calling set() below.
}

void ppp_outputPv::set(ppp_module *_parent, const char *_name, ppp_properties _prop)
{
    module = _parent;
    grants = _prop;
    //Update the parent member which is const so requires some trickery
    *const_cast<ppp_module **>(&parent) = _parent;
    strncpy(buf, _name, sizeof buf);
    buf[sizeof buf - 1] = 0;
}
