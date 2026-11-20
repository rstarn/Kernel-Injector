#include "Injector.h"

/*
 * The engine is intentionally not linked yet. Everything the future
 * implementation needs is already delivered here: a validated x64 PE image
 * in mapped kernel memory, the target PID, the option bits, and a 64-bit
 * result channel back to the client. The planned stages are process lookup,
 * section mapping with relocations, import resolution, and thread creation.
 */

NTSTATUS InjectorExecute(
    const AMGER_INJECT_CONTEXT* Context,
    uint64_t* OutRemoteBase) {
    if (OutRemoteBase != NULL) {
        *OutRemoteBase = 0u;

    }

    if (Context == NULL || Context->ImageBase == NULL ||
        Context->ImageSize == 0u || Context->TargetProcessId == 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_NOT_IMPLEMENTED;
}
