/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _TIMESTAMP_H
#define _TIMESTAMP_H

#include <stdint.h>

void noop();

static inline uint64_t read_ccnt()
{
//Use a fake "memory" dependency to further limit compiler instruction
//scheduling
//But we are avoiding use of barriers/synchronization (e.g. ISB) as this
//normally incurs a lot of overhead
#if defined __arm__
    uint32_t value;
    // Read CCNT Register
    // This requires user space access to be enabled
    __asm __volatile("mrc p15, 0, %0, c9, c13, 0\n" : "=r"(value) : : "memory");
    return value;
#elif defined __aarch64__
    uint64_t value;
    // Read Physical Timer (Cycle) Counter register
    // This requires user space access to be enabled in cntkctl_el1
	__asm __volatile("dsb sy");
	__asm __volatile("MRS %0, PMCCNTR_EL0" : "=r"(value) : : "memory");
	__asm __volatile("dsb sy");
    return value;
#elif defined __x86_64__ || defined __i386__
    uint32_t a, d;
    __asm __volatile("rdtsc" : "=a" (a), "=d" (d));

    return (((uint64_t)a) | (((uint64_t)d) << 32));
#else
#error unsupported architecture
#endif
}

static inline uint64_t getticks()
{
     uint32_t a, d;
     __asm __volatile("rdtsc" : "=a" (a), "=d" (d));

     return (((uint64_t)a) | (((uint64_t)d) << 32));
}

#endif
