/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#define L1_CACHE_REFILL					0
#define L1_CACHE_ACCESS					1
#define L2_CACHE_REFILL					2
#define L2_CACHE_ACCESS					3
#define INSTR_RETIRED					4

#define L1_CACHE_REFILL_EVENT			0x03
#define L1_CACHE_ACCESS_EVENT			0x04
#define L2_CACHE_REFILL_EVENT			0x17
#define L2_CACHE_ACCESS_EVENT			0x16
#define INSTR_RETIRED_EVENT				0x08

#define USER_EVENTS					(1 << 31)

#ifdef __x86_64__
static inline uint64_t __attribute__((always_inline))
	rdtsc(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	asm volatile("rdtsc" :
	"=a" (tsc.lo_32),
	"=d" (tsc.hi_32));

	return tsc.tsc_64;
}
#endif

static inline void __attribute__((always_inline))
pmu_set_pmselr(int r)
{
#ifdef __arm__
	__asm__ __volatile__("MCR p15, 0, %0, c9, c12, 5" :: "r"(r));
#elif __aarch64__
	__asm__ __volatile__("MSR PMSELR_EL0, %0" :: "r"(r));
#endif
}

static inline uint32_t __attribute__((always_inline))
pmu_get_pmselr()
{
	uint32_t r;

#ifdef __arm__
	__asm__ __volatile__("MRC p15, 0, %0, c9, c12, 5" : "=r"(r));
#elif __aarch64__
	__asm__ __volatile__("MRS %0, PMSELR_EL0" : "=r"(r));
#endif

	return r;
}

static inline uint64_t __attribute__((always_inline))
pmu_get_cycle_counter()
{
	uint64_t c;

#ifdef __arm__
	__asm__ __volatile__("MRC p15, 0, %0, c9, c13, 0" : "=r"(c));
#elif __aarch64__
	__asm__ __volatile__("MRS %0, PMCCNTR_EL0" : "=r"(c));
#elif __x86_64__
	c = rdtsc();
#endif
	return c;
}

static inline void __attribute__((always_inline))
pmu_reset_event_counter(int type)
{
	pmu_set_pmselr(type);
#ifdef __arm__
	__asm__ __volatile__("MCR p15, 0, %0, c9, c13, 2" :: "r"(0));
#elif __aarch64__
	__asm__ __volatile__("MSR PMXEVCNTR_EL0, %0" :: "r"(0));
#endif
}

static inline uint32_t __attribute__((always_inline))
pmu_get_event_counter(int type)
{
	uint32_t c = 0;

	pmu_set_pmselr(type);

#ifdef __arm__
	__asm__ __volatile__("MRC p15, 0, %0, c9, c13, 2" : "=r"(c));
#elif __aarch64__
	__asm__ __volatile__("MRS %0, PMXEVCNTR_EL0" : "=r"(c));
#endif

	return c;
}

static inline uint32_t __attribute__((always_inline))
pmu_get_pmxevtyper()
{
	uint32_t r;

#ifdef __arm__
	__asm__ __volatile__("MRC p15, 0, %0, c9, c13, 1" : "=r"(r));
#elif __aarch64__
	__asm__ __volatile__("MRS %0, PMXEVTYPER_EL0" : "=r"(r));
#endif

	return r;
}

static inline void __attribute__((always_inline))
pmu_set_pmxevtyper(uint32_t r)
{
#ifdef __arm__
	__asm__ __volatile__("MCR p15, 0, %0, c9, c13, 1" :: "r"(r));
#elif __aarch64__
	__asm__ __volatile__("MSR PMXEVTYPER_EL0, %0" :: "r"(r));
#endif
}

static inline void __attribute__((always_inline))
pmu_init()
{
#if defined(__arm__) || defined(__aarch64__)
	pmu_set_pmselr(L1_CACHE_REFILL);
	pmu_set_pmxevtyper(L1_CACHE_REFILL_EVENT | USER_EVENTS);
	pmu_set_pmselr(L1_CACHE_ACCESS);
	pmu_set_pmxevtyper(L1_CACHE_ACCESS_EVENT | USER_EVENTS);
	pmu_set_pmselr(L2_CACHE_REFILL);
	pmu_set_pmxevtyper(L2_CACHE_REFILL_EVENT | USER_EVENTS);
	pmu_set_pmselr(L2_CACHE_ACCESS);
	pmu_set_pmxevtyper(L2_CACHE_ACCESS_EVENT | USER_EVENTS);
	pmu_set_pmselr(INSTR_RETIRED);
	pmu_set_pmxevtyper(INSTR_RETIRED_EVENT | USER_EVENTS);
#endif
}
