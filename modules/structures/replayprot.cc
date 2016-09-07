#include "replayprot.h"

struct sliding_window *slwin_alloc()
{
	struct sliding_window *slwin;
	if (!posix_memalign((void **)&(slwin), ODP_CACHE_LINE_SIZE, sizeof(struct sliding_window) + WINSIZE * sizeof(uint64_t)))
		return NULL;

	if (slwin != NULL) {
		// Clear all SN's, 0 is an invalid SN
		memset(slwin->SNV, 0, sizeof(struct sliding_window) + WINSIZE * sizeof(uint64_t));
		return slwin;
	}
	return NULL;
}
