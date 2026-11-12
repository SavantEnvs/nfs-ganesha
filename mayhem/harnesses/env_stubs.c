/* Minimal stand-ins for the daemon-side services the XDR decoders and the config parser call into
 * (logging, per-request context, memory accounting, global parameters). The code under test is linked
 * unmodified; only its environment is replaced. */
#include "config.h"
#include "log.h"
#include "abstract_mem.h"
#include "fsal.h"
#include "nfs_core.h"
#include <pthread.h>

static log_levels_t quiet_levels[COMPONENT_COUNT];

log_levels_t *component_log_level = quiet_levels;
log_levels_t *conditional_component_log_level = quiet_levels;
bool conditional_logging_configured;
__thread struct req_op_context *op_ctx;
pthread_rwlockattr_t default_rwlock_attr;
struct nfs_param nfs_param;

bool is_op_context_conditional_flag_set(void)
{
	return false;
}

void DisplayLogComponentLevel(log_components_t component, const char *file,
			      int line, const char *function,
			      log_levels_t level, const char *format, ...)
{
}

void gsh_mem_stats_update_alloc(void *p, mem_components_t comp,
				const char *file, int line,
				const char *function)
{
}

void gsh_mem_stats_update_free(void *p, mem_components_t comp,
			       const char *file, int line,
			       const char *function)
{
}
