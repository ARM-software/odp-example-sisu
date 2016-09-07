/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include "ppp_graph.h"
#include "ppp_module.h"
#include "ppp_if.h"

ppp_graph::ppp_graph(const char *n, unsigned _nifs) :
    nitems(0),
    maxitems(0),
    poll_table(NULL),
    poll_mods(NULL),
    mod_list(NULL),
    nifs(_nifs),
    name(n)
{
    if_array = new ppp_if *[nifs];
    for (unsigned i = 0; i < nifs; i++)
    {
	if_array[i] = NULL;
    }

	odp_thrmask_t thrmask;
	odp_thrmask_zero(&thrmask);
	odp_schedule_group_create(n, &thrmask);
}

ppp_graph::~ppp_graph()
{
    if (poll_table != NULL)
    {
	delete poll_table;
    }
    if (poll_mods != NULL)
    {
	delete poll_mods;
    }
    delete if_array;
}

void ppp_graph::register_sd(ppp_module *mod, int sd, int events)
{
    if (nitems == maxitems)
    {
	maxitems += 5;
	pollfd *new_poll_table = new pollfd[maxitems];
	ppp_module **new_poll_mods = new ppp_module *[maxitems];
	for (uint32_t i = 0; i < nitems; i++)
	{
	    new_poll_table[i] = poll_table[i];
	    new_poll_mods[i] = poll_mods[i];
	}
	poll_table = new_poll_table;
	poll_mods = new_poll_mods;
    }
    poll_table[nitems].fd = sd;
    poll_table[nitems].events = events;
    poll_table[nitems].revents = 0;
    poll_mods[nitems] = mod;
    nitems++;
}

void ppp_graph::unregister_sd(int sd)
{
    for (uint32_t i = 0; i < nitems; i++)
    {
	if (poll_table[i].fd == sd)
	{
	    for (uint32_t j = i + 1; j < nitems; j++)
	    {
		poll_table[j - 1] = poll_table[j];
		poll_mods[j - 1] = poll_mods[j];
	    }
	    nitems--;
	    return;
	}
    }
}

void ppp_graph::insert_module(ppp_module *mod)
{
    mod->next = mod_list;
    mod_list = mod;
}

void ppp_graph::remove_module(ppp_module *mod)
{
    ppp_module **pptr = &mod_list;
    while (*pptr != NULL)
    {
	if (*pptr == mod)
	{
	    *pptr = mod->next;
	    break;
	}
	pptr = &(*pptr)->next;
    }
}

void ppp_graph::traverse_modules(void (*apply)(void *, ppp_module *), void *handle)
{
    ppp_module *ptr = mod_list;
    while (ptr != NULL)
    {
	apply(handle, ptr);
	ptr = ptr->next;
    }
}

void ppp_graph::execute()
{
	odp_thrmask_t thrmask;
	odp_thrmask_zero(&thrmask);
	odp_thrmask_set(&thrmask, odp_thread_id());
	odp_schedule_group_join(odp_schedule_group_lookup(name), &thrmask);

    while (nitems != 0)
    {
	int ret = poll(poll_table, nitems, -1/*Forever*/);
	if (ret > 0)
	{
	    for (uint32_t i = 0; i < nitems; i++)
	    {
		if (poll_table[i].revents != 0)
		{
		    poll_mods[i]->sd_handler(poll_table[i].fd, poll_table[i].revents);
		    poll_table[i].revents = 0;
		}
	    }
	}
    }
}

void ppp_graph::list_if()
{
    ppp_if::print_if_hdr();
    for (unsigned i = 0; i < nifs; i++)
    {
	if (if_array[i] != NULL)
	{
	    if_array[i]->print_if(i);
	}
    }
}

const char *
ppp_graph::ifx2name(int32_t ifx)
{
    if (ifx > 0 && (unsigned)ifx < nifs)
    {
	return if_array[ifx]->name;
    }
    return "?";

}

void
ppp_graph::add_if(ppp_if *ifp, int32_t ifx)
{
    if (ifx == PPP_INDEX_INVALID || (unsigned)ifx >= nifs || ifx < 0)
    {
	fprintf(stderr, "%s: Invalid interface index %d\n", ifp->name, ifx);
	abort();
    }
    if (if_array[ifx] != NULL)
    {
	fprintf(stderr, "%s: Interface index %d already in use\n", ifp->name, ifx);
	abort();
    }
    if_array[ifx] = ifp;
}
