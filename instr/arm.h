/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _ARM_H_
#define _ARM_H_

#define CACHE_LINE_SIZE		64

/* Memory barriers */
#define ARM_DMB_ST() do { \
__asm__ __volatile__ ("dmb st" : : : "memory"); \
} while (0)

#define ARM_DMB() do { \
__asm__ __volatile__ ("dmb sy" : : : "memory"); \
} while (0)

#define ARM_DSB() do { \
__asm__ __volatile__ ("dsb sy" : : : "memory"); \
} while (0)

#define ARM_ISB() { do { \
__asm__ __volatile__ ("isb" : : : "memory"); \
} while (0)

#define FULL_MB() ARM_ISB()
#define RMB() ARM_DMB()
#define WMB() ARM_DMB_ST()
#define MB() ARM_DMB()

/* Loads and stores */
#define ARM_LD(value, base) do { \
__asm__ __volatile__("LDR %0, [%1]" : "=&r"(value) : "r"(base) : "cc", "memory"); \
} while (0)

#define ARM_ST(value, base) do { \
__asm__ __volatile__("STR %0, [%1]" : : "r"(value), "r"(base) : "cc", "memory"); \
} while (0)

#ifdef __arm__
#define ARM_LL(value, base) do { \
__asm__ __volatile__("LDREX %0, [%1]" : "=&r"(value) : "r"(base) : "cc", "memory"); \
} while (0)

#define ARM_SC(result, value, base) do { \
__asm__ __volatile__("STREX %0, %1, [%2]" : "=&r"(result) : "r"(value), "r"(base) : "cc", "memory"); \
} while (0)

#elif __aarch64__
#define ARM_LL(value, base) do { \
__asm__ __volatile__("LDXR %w0, [%1]" : "=&r"(value) : "r"(base) : "cc", "memory"); \
} while (0)

#define ARM_SC(result, value, base) do { \
__asm__ __volatile__("STXR %w0, %w1, [%2]" : "=&r"(result) : "r"(value), "r"(base) : "cc", "memory"); \
} while (0)
#endif

#define ARM_LLA(value, base) do { \
__asm__ __volatile__("LDAEX %w0, [%1]" : "=&r"(value) : "r"(base) : "cc", "memory"); \
} while (0)

#define ARM_SCR(result, value, base) do { \
__asm__ __volatile__("STLEX %w0, %w1, [%2]" : "=&r"(result) : "r"(value), "r"(base) : "cc", "memory"); \
} while (0)

#ifdef __arm__
#define ARM_LA(value, base) do { \
	ARM_LD(value, base); \
	ARM_DMB_ST(); \
} while (0)

#define ARM_SR(value, base) do { \
	ARM_DMB_ST(); \
	ARM_ST(value, base); \
} while (0)

#elif __aarch64__
#define ARM_LA(value, base) do { \
__asm__ __volatile__("LDAR %w0, [%1]" : "=&r"(value) : "r"(base) : "cc", "memory"); \
} while (0)

#define ARM_SR(value, base) do { \
__asm__ __volatile__("STLR %w0, [%1]" : : "r"(value), "r"(base) : "cc", "memory"); \
} while (0)

#endif

#endif
