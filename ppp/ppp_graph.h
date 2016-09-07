/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

//Packet Processing Pipeline - module definitions

#ifndef _PPP_GRAPH_H
#define _PPP_GRAPH_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

struct pollfd;
class ppp_module;
class ppp_if;

class ppp_graph
{
    //Array of pollfd suitable for poll()
    uint32_t nitems;
    uint32_t maxitems;
    pollfd *poll_table;
    ppp_module **poll_mods;
    //Single linked list of all modules
    ppp_module *mod_list;
    //Max number of interfaces in if_array
    uint32_t nifs;
public:
    const char * const name;
    ppp_if **if_array;

    ppp_graph(const char *_name, unsigned _nifs);
    virtual ~ppp_graph();
    ppp_graph(const ppp_graph & _mod) ://Copy constructor
	name(NULL)
    {
	abort();
    }
    ppp_graph &operator=(const ppp_graph&)//Assignment operator
    {
	abort();
    }

    void register_sd(ppp_module *, int sd, int events);
    void unregister_sd(int sd);
    virtual void execute();

    void insert_module(ppp_module *);
    void remove_module(ppp_module *);
    void traverse_modules(void (*apply)(void *, ppp_module *), void *);

    void add_if(ppp_if *ifp, int32_t ifx);
    const char *ifx2name(int32_t ifx);
    void list_if();
};

#endif //_PPP_GRAPH_H
