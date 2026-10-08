#ifndef QUOTERN_H
#define QUOTERN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Quotern bridge ABI v1. Every returned char * is Rust-allocated and released exactly once by
 * quotern_string_free. Inputs are NUL-terminated UTF-8 borrowed for the call only. */

typedef struct QuoternEngine QuoternEngine;
typedef struct QuoternCancel QuoternCancel;

uint32_t quotern_abi_version(void);

/* On failure *out is NULL. The returned envelope is never NULL. */
char *quotern_engine_open(const char *config_json, QuoternEngine **out);

/* NULL is a no-op. No call may be in flight. */
void quotern_engine_close(QuoternEngine *engine);

/* Never returns NULL. A NULL cancel means not cancellable. */
char *quotern_call(QuoternEngine *engine, const char *method, const char *request_json,
                   const QuoternCancel *cancel);

QuoternCancel *quotern_cancel_new(void);
void quotern_cancel_trigger(const QuoternCancel *cancel);
void quotern_cancel_free(QuoternCancel *cancel);

/* NULL is a no-op. */
void quotern_string_free(char *text);

#ifdef __cplusplus
}
#endif

#endif
