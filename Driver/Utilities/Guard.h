#ifndef AMGER_GUARD_H
#define AMGER_GUARD_H

/*
 * Guard.h - containment for kernel-mode memory faults.
 *
 * Contract: executes a caller-supplied worker inside __try/__except, logs the
 * real exception code, and classifies the fault: an expected probe fault
 * (MmProbeAndLockPages on a bad user range) becomes STATUS_INVALID_PARAMETER,
 * any unexpected fault becomes STATUS_UNSUCCESSFUL.
 * Inputs: Worker function pointer, an opaque Context pointer, and a flag
 *         saying whether an access violation is the expected probe rejection.
 * Outputs: the worker's NTSTATUS, or a classified status on exception.
 * Failure modes: a null Worker returns STATUS_INVALID_PARAMETER; exceptions are
 * swallowed by design so a malformed user virtual address cannot bugcheck.
 */

#include <wdm.h>

typedef NTSTATUS (* AMGER_EXCEPTION_GUARDED_WORKER)(PVOID Context);

/*
 * Contract: runs Worker inside a __try/__except frame and classifies faults.
 * Inputs: Worker callback, its opaque Context, and ExpectProbeFault - TRUE only
 *         for workers that probe user memory (MmProbeAndLockPages), where an
 *         access violation is the expected rejection path.
 * Outputs: the worker's NTSTATUS; on exception, STATUS_INVALID_PARAMETER for an
 *          expected probe fault or STATUS_UNSUCCESSFUL for an unexpected fault.
 *          The exception code and class are logged via DbgPrintEx.
 * Failure modes: STATUS_INVALID_PARAMETER for a null Worker.
 */

NTSTATUS GuardExecute(
    AMGER_EXCEPTION_GUARDED_WORKER Worker,
    PVOID Context,
    BOOLEAN ExpectProbeFault);

#endif /* AMGER_GUARD_H */
