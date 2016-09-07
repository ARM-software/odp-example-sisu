/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _ARCH_H_
#define _ARCH_H_

#if defined(__arm__) || defined(__aarch64__)
#include "arm.h"
#elif defined(__x86_64__)
#include "x86.h"
#else
#error "Architecture not supported"
#endif

#define CACHE_LINE_SIZE		64

#define NOP()  do { \
	__asm__ __volatile__ ("nop"); \
} while (0)

#define COMPILER_BARRIER()  do { \
	__asm__ __volatile__ ("" : : : "memory"); \
} while (0)

#endif
