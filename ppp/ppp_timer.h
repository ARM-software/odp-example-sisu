/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _PPP_TIMER_H
#define _PPP_TIMER_H

#include <stdint.h>
#include <odp.h>
#include "odp_src.h"

typedef uint64_t ppp_timer_value;
#define TICK_INVALID (~0ULL)

class ppp_timer;

class ppp_timer_pool
{
    odp_timer_pool_t tp;
public:
    ppp_timer_value get_current_tick()
    {
	return odp_timer_current_tick(tp);
    }
    ppp_timer_value ns_to_tick(uint64_t ns)
    {
	return odp_timer_ns_to_tick(tp, ns);
    }
    ppp_timer_pool(const char *name, uint32_t res_ns, uint32_t ntimers)
    {
	odp_timer_pool_param_t params;
	memset(&params, 0, sizeof(params));
	params.res_ns = res_ns;
	params.min_tmo = 0;
	params.max_tmo = 50000 * 1000000000ULL;//50000 seconds max timeout
	params.num_timers = ntimers;
	params.priv = false;//shared
	params.clk_src = ODP_CLOCK_CPU;
	tp = odp_timer_pool_create(name, &params);
	if (tp == ODP_TIMER_POOL_INVALID)
	    perror("odp_timer_pool_create"), abort();
	//Start all timer pools created so far
	odp_timer_pool_start();
    }
    ~ppp_timer_pool()
    {
	if (tp != ODP_TIMER_POOL_INVALID)
	{
	    odp_timer_pool_destroy(tp);
	}
    }
    friend class ppp_timer;
};

class ppp_timer : public odp_src_input
{
    odp_timer_t tim;
    odp_event_t ev;
    uint64_t req_tick; //Expiration tick or TICK_INVALID
public:
    //Attempt to allocate a timer, return true on success
    bool alloc(ppp_module *mod,   //Call-back module
	       odp_callback_f func,//Call-back member function
	       void *ctx,	 //Call-back context pointer
	       ppp_timer_pool *tp,//Timer pool to allocate timer from
	       odp_pool_t pool,   //Pool to allocate timeout from
	       odp_queue_t queue) //Queue to deliver timeouts on
    {
	module = mod;
	function = func;
	context = ctx;
	tim = odp_timer_alloc(tp->tp, queue, static_cast<void *>(this));
	if (tim != ODP_TIMER_INVALID)
	{
	    odp_timeout_t tmo = odp_timeout_alloc(pool);
	    if (tmo != ODP_TIMEOUT_INVALID)
	    {
		ev = odp_timeout_to_event(tmo);
		return true;
	    }
	    (void)odp_timer_free(tim);
	}
	return false;
    }
    void free()
    {
	if (tim != ODP_TIMER_INVALID)
	{
	    odp_event_t ev2 = odp_timer_free(tim);
	    if (ev2 != ODP_EVENT_INVALID)
	    {
		odp_timeout_free(odp_timeout_from_event(ev));
	    }
	    //FIXME why two frees?
	    if (ev != ODP_EVENT_INVALID)
	    {
		odp_timeout_free(odp_timeout_from_event(ev));
		ev = ODP_EVENT_INVALID;
	    }
	    tim = ODP_TIMER_INVALID;
	    req_tick = TICK_INVALID;
	}
    }
    //Arm timer with relative time
    void set_rel(ppp_timer_value timeout)
    {
	assert(tim != ODP_TIMER_INVALID);
	int rc;
	while ((rc = odp_timer_set_rel(tim, timeout, &ev)) ==
		ODP_TIMER_TOOEARLY)
	{
	    //Try again with next tick
	    timeout++;
	}
	if (rc == ODP_TIMER_TOOLATE)
	{
	    abort();
	}
	//else rc == ODP_TIMER_SUCCESS || rc == ODP_TIMER_NOEVENT
	//ODP_TIMER_NOEVENT => timer expired but not received
	req_tick = timeout;
    }
    void cancel()
    {
	assert(tim != ODP_TIMER_INVALID);
	odp_event_t tmo_ev;
	int rc = odp_timer_cancel(tim, &tmo_ev);
	if (rc == 0)
	{
	    //Success
	    assert(ev == ODP_EVENT_INVALID);
	    ev = tmo_ev;
	    assert(odp_timeout_user_ptr(odp_timeout_from_event(ev)) ==
		   static_cast<void *>(this));
	}
	//Else timer inactive or already expired
	//Invalidate request timeout tick
	req_tick = TICK_INVALID;
    }
    void return_tmo(odp_event_t user_ev)
    {
	assert(tim != ODP_TIMER_INVALID);
	assert(ev == ODP_EVENT_INVALID);
	ev = user_ev;
    }

    ppp_timer()
    {
	tim = ODP_TIMER_INVALID;
	ev = ODP_EVENT_INVALID;
	req_tick = TICK_INVALID;
    }
    ~ppp_timer()
    {
	free();
    }
};

#endif
