/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _COMPILER_H
#define _COMPILER_H

// likely/unlikely - Provide static branch prediction hints to the compiler.

#if defined __GNUC__
#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)
#else
#define likely(x)    x
#define unlikely(x)  x
#endif

// prefetch_r/w - Cache prefetching hints
#if defined __ARM_ARCH && __ARM_ARCH >= 7
#ifdef ARM_USE_PLDW
//Generate PLDW directly as GCC 4.8 does not support it
#define prefetch_w(ptr) __asm __volatile("pldw [%[addr]]\n" :: [addr] "r" ((ptr)) : )
#else
//Not all ARMv7 implementations support PLDW
#define prefetch_w(ptr) __asm __volatile("pld [%[addr]]\n" :: [addr] "r" ((ptr)) : )
#endif
#else //Fall back to the standard builtin_prefetch implementation
#define prefetch_w(ptr) __builtin_prefetch((ptr), 1, 0)
#endif
#define prefetch_r(ptr) __builtin_prefetch((ptr), 0, 0)

#endif //_COMPILER_H
