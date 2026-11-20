#include "Guard.h"

/*
 * Fault classification inside GuardExecute.
 *
 * A probe fault is the one expected case: RegistrationWorker calls
 * MmProbeAndLockPages on a user address, which deliberately raises
 * STATUS_ACCESS_VIOLATION for a bad range. That maps to a clean
 * STATUS_INVALID_PARAMETER (the registration request was rejected).
 *
 * Any other code - or an access violation from a worker that never probes
 * user memory (KickWorker / WriteStatusWorker operate only on the already
 * MDL-locked region) - is unexpected. It is logged loudly with its code and
 * the worker pointer and mapped to STATUS_UNSUCCESSFUL so the caller can tell
 * an internal fault from a rejected request. Previously every exception was
 * silently flattened to STATUS_ACCESS_VIOLATION with no diagnostic.
 *
 * MSVC restricts what an __except FILTER expression may call, so the filter
 * here only captures GetExceptionCode() into a local (a simple assignment,
 * which is permitted). All classification and logging happens inside the
 * handler block, where the captured code is an ordinary local variable.
 */

NTSTATUS GuardExecute(
    AMGER_EXCEPTION_GUARDED_WORKER Worker,
    PVOID Context,
    BOOLEAN ExpectProbeFault) {
    ULONG exceptionCode = 0u;

    if (Worker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        return Worker(Context);
    }
    __except (exceptionCode = (ULONG)GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        const BOOLEAN isAv = (exceptionCode == (ULONG)STATUS_ACCESS_VIOLATION);
        const BOOLEAN wasProbe = (BOOLEAN)(ExpectProbeFault && isAv);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[Ameger] GuardExecute: worker=%p code=0x%08X class=%s\n",
                   (PVOID)Worker, exceptionCode,
                   wasProbe ? "expected-probe-fault" : "UNEXPECTED-kernel-fault");

        /* A probed user range that was rejected is an ordinary invalid request.
         * Everything else is an internal fault and must be reported as such. */

        return wasProbe ? STATUS_INVALID_PARAMETER : STATUS_UNSUCCESSFUL;
    }
}
