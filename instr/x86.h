/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _X86_H_
#define _X86_H_

#define CACHE_LINE_SIZE		64

#define X86_MB() __asm__ __volatile__("lfence" ::: "memory")
#define X86_RMB() X86_MB()
#define X86_WMB() __asm__ __volatile__("" ::: "memory")
#define X86_WC_WMB() __asm__ __volatile__("sfence" ::: "memory")

#define FULL_MB() X86_WC_WMB()
#define RMB() X86_RMB()
#define WMB() X86_WMB()
#define MB() X86_MB()
#endif
