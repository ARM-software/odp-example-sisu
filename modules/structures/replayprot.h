#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <odp.h>

#include <stdio.h>

#define INVALID_SN ((uint64_t)-1)
#define WINSIZE 1024
#define WINMASK (WINSIZE - 1)
#define SWIZZLE true

struct sliding_window {
	uint64_t SNV[1] ODP_ALIGNED_CACHE;
};

enum reply_result {
	pass, replay, stale
};

struct sliding_window *slwin_alloc();

#if defined __ARM_ARCH
static inline
uint64_t ll(uint64_t *var)
{
	uint64_t old;
#if __ARM_ARCH == 7
	__asm __volatile("ldrexd %0, %H0, [%1]"
		: "=&r" (old)
		: "r" (var)
		: "cc");
#elif __ARM_ARCH == 8
	__asm __volatile("ldxr %x0, [%x1]"
		: "=&r" (old)
		: "r" (var)
		: "cc");
#endif
	return old;
}

static inline
uint32_t sc(uint64_t *var, uint64_t new_value)
{
	uint32_t ret;
#if __ARM_ARCH == 7
	__asm __volatile("strexd %0, %1, %H1, [%2]"
		: "=&r" (ret)
		: "r" (new_value), "r" (var)
		: "cc");
#elif __ARM_ARCH == 8
	__asm __volatile("stxr %w0, %x1, [%x2]"
		: "=&r" (ret)
		: "r" (new_value), "r" (var)
		: "cc");
#endif
	return ret;
}
#endif

//return old value before max operation, relaxed memory order
static inline
uint64_t atomic_fetch_max_rlx(uint64_t *var, uint64_t v)
{
#if defined __ARM_ARCH && __ARM_ARCH >= 7
	for (;;) {
		uint64_t old = ll(var);
		uint64_t max = old > v ? old : v;
		if (odp_likely(!sc(var, max)))
			return old;
	}
#else // Emulate using CAS
	uint64_t old = __atomic_load_n(var, __ATOMIC_RELAXED);
	for (;;) {
		if (odp_likely(v > old)) {
			// Attempt to store 'v' in '*var'
			if (__atomic_compare_exchange_n(var,
							&old,
							v,
							/*weak=*/true,
							__ATOMIC_RELAXED,
							__ATOMIC_RELAXED)) {
				return old;
			}
		} else {
			return old;
		}
	}
#endif
}

static inline
uint32_t extract(uint32_t v, uint32_t msb, uint32_t lsb)
{
	uint32_t width = msb - lsb + 1;
	uint32_t mask = (1U << width) - 1U;
	return v & (mask << lsb);
}

static uint32_t sn_to_index(uint64_t sn)
{
	if (SWIZZLE) {
		// Compute index to SNV array but consecutive SN's will be
		// located in different cache lines
		// There are some dependencies on cache line size and
		// size of the replay window here...
		return (extract(sn, 31, 6) |
			extract(sn, 5, 3) >> 3 |
			extract(sn, 2, 0) << 3) & WINMASK;
	} else {
		// Compute index into SNV array, consecutive SN's will occupy
		// consecutive memory locations
		return sn & WINMASK;
	}
}

static inline
enum reply_result test_and_set(struct sliding_window *slwin, uint64_t SN)
{
	uint32_t index = sn_to_index(SN);
	uint64_t OSN = atomic_fetch_max_rlx(&slwin->SNV[index], SN);

	if (odp_likely(SN > OSN || OSN == INVALID_SN))
		return pass;
	else if (SN == OSN)
		return replay; // Packet counted and discarded
	else
		return stale; // Packet discarded
}

static inline
enum reply_result check_for_replay(struct sliding_window *slwin, uint64_t SN)
{
	return test_and_set(slwin, SN);
}
