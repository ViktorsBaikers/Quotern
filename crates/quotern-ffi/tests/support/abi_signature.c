/* Compiled by contract_v1.rs against the canonical header and a generated include that spells the
 * signature derived from each ACTUAL Rust export. A header declaration that differs in width,
 * arity or constness makes a _Static_assert fail and clang exit non-zero. */
#include "quotern.h"
#include QUOTERN_RUST_SIGNATURES

#define ASSERT_SIG(name) \
    _Static_assert(_Generic(&name, SIG_##name : 1, default : 0), "signature mismatch: " #name)

ASSERT_SIG(quotern_abi_version);
ASSERT_SIG(quotern_engine_open);
ASSERT_SIG(quotern_engine_close);
ASSERT_SIG(quotern_call);
ASSERT_SIG(quotern_cancel_new);
ASSERT_SIG(quotern_cancel_trigger);
ASSERT_SIG(quotern_cancel_free);
ASSERT_SIG(quotern_string_free);

int quotern_probe_unused(void) { return 0; }
