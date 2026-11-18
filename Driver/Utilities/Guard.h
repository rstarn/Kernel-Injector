#ifndef AMGER_GUARD_H
#define AMGER_GUARD_H

/*
 * Guard.h - containment for kernel-mode memory faults.
 *
 * Contract: executes a caller-supplied worker inside __try/__except and converts
 * any hardware or software exception into STATUS_ACCESS_VIOLATION.
 * Inputs: Worker function pointer and an opaque Context pointer.
 * Outputs: the worker's NTSTATUS, or STATUS_ACCESS_VIOLATION on exception.
 * Failure modes: a null Worker returns STATUS_INVALID_PARAMETER; exceptions are
 * swallowed by design so a malformed user virtual address cannot bugcheck.
 */

#include <wdm.h>

typedef NTSTATUS (* AMGER_EXCEPTION_GUARDED_WORKER)(PVOID Context);

/*
 * Contract: runs Worker inside a __try/__except frame.
 * Inputs: Worker callback and its opaque Context.
 * Outputs: the worker's NTSTATUS, or STATUS_ACCESS_VIOLATION on exception.
 * Failure modes: STATUS_INVALID_PARAMETER for a null Worker.
 */
NTSTATUS GuardExecute(
    AMGER_EXCEPTION_GUARDED_WORKER Worker,
    PVOID Context);

/* Begin/end markers for inline guarded regions that must return directly. */
#define AMGER_SEH_BEGIN __try {
#define AMGER_SEH_END } __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

#endif /* AMGER_GUARD_H */
