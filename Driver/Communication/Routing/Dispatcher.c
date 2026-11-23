#include "Dispatcher.h"
#include "../../Execution/Injector.h"
#include "../../Utilities/Parser/Format.h"

/* INJECT consumes the full payload contract: a real target, a bounded payload
 * at the fixed offset, only known option bits, and synchronous completion.
 * The bridge has already bounds-checked the range inside the registered MDL;
 * this layer validates the command-level semantics. Phases 1 through 4 are
 * linked; phases 5-8 are deferred, so a valid request reports NOT_IMPLEMENTED
 * after the image has been mapped, relocated, imported and sealed. */

static NTSTATUS ValidateInjectRequest(const AMGER_DISPATCH_CONTEXT* Context) {
    const AMGER_COMMAND_SNAPSHOT* snapshot = Context->Snapshot;

    if (snapshot->TargetProcessId == 0u ||
        snapshot->PayloadVirtualAddress == 0u ||
        snapshot->PayloadSize == 0u ||
        snapshot->PayloadSize > (uint64_t)AMGER_MAXIMUM_PAYLOAD_SIZE ||
        snapshot->PayloadSize > (uint64_t)SIZE_MAX ||
        Context->PayloadSystemAddress == NULL ||
        Context->PayloadSize != (SIZE_T)snapshot->PayloadSize ||
        Context->PayloadOffset != (SIZE_T)AMGER_PAYLOAD_OFFSET ||
        (snapshot->Options & ~AMGER_OPTION_KNOWN_MASK) != 0u ||
        snapshot->CompletionEventHandle != 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS DispatcherDispatch(
    AMGER_DISPATCH_CONTEXT* Context,
    uint32_t* OutStatus) {
    const AMGER_COMMAND_SNAPSHOT* snapshot;
    NTSTATUS status;

    if (OutStatus == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Context == NULL || Context->Snapshot == NULL) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        snapshot = Context->Snapshot;
        Context->ParserImageValid = FALSE;
        Context->ParserStatus = 0u;
        RtlZeroMemory(&Context->AllocReport, sizeof(Context->AllocReport));
        RtlZeroMemory(&Context->MapReport, sizeof(Context->MapReport));
        RtlZeroMemory(&Context->RelocReport, sizeof(Context->RelocReport));
        RtlZeroMemory(&Context->ImportReport, sizeof(Context->ImportReport));
        Context->StageId = (uint16_t)AMGER_LOG_ID_HEADER_VALIDATE;

        if (snapshot->Magic != Context->Magic ||
            snapshot->Version != AMGER_PROTOCOL_VERSION ||
            snapshot->Status != AMGER_STATUS_PENDING) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            Context->StageId = (uint16_t)AMGER_LOG_ID_COMMAND_DECODE;
            switch (snapshot->Command) {
            case AMGER_COMMAND_PING:
                Context->StageId = (uint16_t)AMGER_LOG_ID_PING;

                /* PING has no payload or target. Reject nonzero fields rather
                 * than silently accepting data that this command never uses. */

                status = (snapshot->PayloadVirtualAddress == 0u &&
                          snapshot->PayloadSize == 0u &&
                          snapshot->TargetProcessId == 0u &&
                          snapshot->Options == 0u &&
                          snapshot->CompletionEventHandle == 0u)
                             ? STATUS_SUCCESS
                             : STATUS_INVALID_PARAMETER;
                break;
            case AMGER_COMMAND_INJECT: {
                AMGER_INJECT_CONTEXT inject;
                AMGER_PE_IMAGE image;
                uint64_t remoteBase = 0u;

                RtlZeroMemory(&inject, sizeof(inject));

                Context->StageId = (uint16_t)AMGER_LOG_ID_INJECT;
                status = ValidateInjectRequest(Context);
                if (NT_SUCCESS(status)) {
                    Context->StageId = (uint16_t)AMGER_LOG_ID_PAYLOAD_IMAGE;
                    status = PeParseAndValidate(Context->PayloadSystemAddress,
                                                Context->PayloadSize,
                                                &image);
                    Context->ParserStatus = (uint32_t)status;
                    if (NT_SUCCESS(status)) {
                        Context->ParserImage = image;
                        Context->ParserImageValid = TRUE;
                    }
                }
                if (NT_SUCCESS(status)) {
                    inject.TargetProcessId = snapshot->TargetProcessId;
                    inject.Options = snapshot->Options;
                    inject.ImageBase = Context->PayloadSystemAddress;
                    inject.ImageSize = Context->PayloadSize;
                    inject.Image = &image;
                    inject.AllocReport = &Context->AllocReport;
                    inject.MapReport = &Context->MapReport;
                    inject.RelocReport = &Context->RelocReport;
                    inject.ImportReport = &Context->ImportReport;
                    Context->StageId = (uint16_t)AMGER_LOG_ID_INJECT;
                    status = InjectorExecute(&inject, &remoteBase);
                    if (NT_SUCCESS(status)) {
                        Context->ResultValue = remoteBase;
                    }
                }
                break;
            }
            case AMGER_COMMAND_EJECT:
                Context->StageId = (uint16_t)AMGER_LOG_ID_EJECT;
                status = STATUS_NOT_IMPLEMENTED;
                break;
            case AMGER_COMMAND_STATUS:
                Context->StageId = (uint16_t)AMGER_LOG_ID_STATUS_COMMAND;

                /* STATUS has no payload or target. Publish the first lifecycle
                 * teardown failure in the result slot so a client can observe
                 * it; the command itself succeeds when nothing has failed. */

                status = (snapshot->PayloadVirtualAddress == 0u &&
                          snapshot->PayloadSize == 0u &&
                          snapshot->TargetProcessId == 0u &&
                          snapshot->Options == 0u &&
                          snapshot->CompletionEventHandle == 0u)
                             ? STATUS_SUCCESS
                             : STATUS_INVALID_PARAMETER;
                if (NT_SUCCESS(status)) {
                    Context->ResultValue = (uint64_t)Context->LastFailure;
                }
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
    }

    *OutStatus = (uint32_t)status;

    return status;
}
