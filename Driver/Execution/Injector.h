#ifndef AMGER_INJECTOR_H
#define AMGER_INJECTOR_H

/*
 * Injector.h - execution plug point for AMGER_COMMAND_INJECT.
 *
 * Contract: consumes a validated PE image already mapped into kernel memory
 * and reports the remote module base on success. Validation of the request
 * and of the PE headers happens in the dispatcher before this call, so the
 * implementation can assume a well-formed x64 image and a live target PID.
 * Inputs: process id, option bits, kernel image base and image size.
 * Outputs: NTSTATUS and the remote base address in OutRemoteBase.
 * Failure modes: STATUS_NOT_IMPLEMENTED while phases 5-8 are deferred.
 */

#include <wdm.h>
#include "../../Shared/Protocol.h"
#include "../Utilities/Parser/Format.h"

typedef struct _AMGER_INJECT_CONTEXT {
    uint32_t TargetProcessId;
    uint32_t Options;
    PVOID ImageBase;
    SIZE_T ImageSize;
    const AMGER_PE_IMAGE* Image;
    PAMGER_ALLOC_REPORT AllocReport;
    PAMGER_MAP_REPORT MapReport;
    PAMGER_RELOC_REPORT RelocReport;
    PAMGER_IMPORT_REPORT ImportReport;
} AMGER_INJECT_CONTEXT, * PAMGER_INJECT_CONTEXT;

NTSTATUS InjectorExecute(
    const AMGER_INJECT_CONTEXT* Context,
    uint64_t* OutRemoteBase);

#endif /* AMGER_INJECTOR_H */
