/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _GLOBALS_H
#define _GLOBALS_H

#include "odp.h"
#include "ppp_timer.h"

#define RUN_TIME_S	5

extern odp_pool_t tmo_pool;
extern ppp_timer_pool *timer_pool;

#endif
