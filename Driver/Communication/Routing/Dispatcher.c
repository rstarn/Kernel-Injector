#include "Dispatcher.h"
#include "../../Execution/Injector.h"

/* INJECT consumes the full payload contract: a real target, a bounded payload
 * at the fixed offset, only known option bits, and synchronous completion.
 * The bridge has already bounds-checked the range inside the registered MDL;
 * this layer validates the command-level semantics. The mapping engine itself
 * is linked in a later build, so a valid request reports NOT_IMPLEMENTED. */
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

/* Kernel headers do not expose the user-mode IMAGE_* types, so the PE fields
 * are read byte-wise. Alignment is irrelevant and a malformed image cannot
 * fault the guarded worker. */
static uint32_t ReadLe32(const PUCHAR bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint16_t ReadLe16(const PUCHAR bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

/* Offsets: DOS e_magic 0, e_lfanew 0x3C; PE signature 0, FileHeader at 4
 * (Machine 0, Sections 2), OptionalHeader at 24 (Magic 0, SizeOfImage 56,
 * SizeOfHeaders 60). */
#define AMGER_PE_MINIMUM_SIZE 88u

static NTSTATUS ValidatePeImage(const AMGER_DISPATCH_CONTEXT* Context) {
    const PUCHAR image = (const PUCHAR)Context->PayloadSystemAddress;
    uint32_t peOffset;
    PUCHAR nt;

    if (Context->PayloadSize < AMGER_PE_MINIMUM_SIZE ||
        ReadLe16(image) != 0x5A4Du) { /* MZ */
        return STATUS_INVALID_PARAMETER;
    }

    peOffset = ReadLe32(image + 0x3Cu);
    if (peOffset == 0u || peOffset > Context->PayloadSize - AMGER_PE_MINIMUM_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    nt = image + peOffset;
    if (ReadLe32(nt) != 0x00004550u ||       /* PE\0\0 */
        ReadLe16(nt + 4u) != 0x8664u ||      /* IMAGE_FILE_MACHINE_AMD64 */
        ReadLe16(nt + 24u) != 0x020Bu ||     /* PE32+ */
        ReadLe16(nt + 6u) == 0u ||
        ReadLe16(nt + 6u) > 96u) {
        return STATUS_INVALID_PARAMETER;
    }

    {
        const uint32_t sizeOfImage = ReadLe32(nt + 24u + 56u);
        const uint32_t sizeOfHeaders = ReadLe32(nt + 24u + 60u);

        if (sizeOfHeaders < AMGER_PE_MINIMUM_SIZE ||
            sizeOfHeaders > Context->PayloadSize ||
            sizeOfImage < sizeOfHeaders ||
            sizeOfImage > (512u * 1024u * 1024u)) {
            return STATUS_INVALID_PARAMETER;
        }

        /* The section table must fit inside the declared headers. */
        {
            const uint16_t optionalSize = ReadLe16(nt + 20u);
            const uint64_t sectionEnd = (uint64_t)peOffset + 24u + optionalSize +
                                        (uint64_t)ReadLe16(nt + 6u) * 40u;
            if (optionalSize < 112u || sectionEnd > sizeOfHeaders) {
                return STATUS_INVALID_PARAMETER;
            }
        }
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
                uint64_t remoteBase = 0u;

                Context->StageId = (uint16_t)AMGER_LOG_ID_INJECT;
                status = ValidateInjectRequest(Context);
                if (NT_SUCCESS(status)) {
                    Context->StageId = (uint16_t)AMGER_LOG_ID_PAYLOAD_IMAGE;
                    status = ValidatePeImage(Context);
                }
                if (NT_SUCCESS(status)) {
                    inject.TargetProcessId = snapshot->TargetProcessId;
                    inject.Options = snapshot->Options;
                    inject.ImageBase = Context->PayloadSystemAddress;
                    inject.ImageSize = Context->PayloadSize;
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
                status = STATUS_NOT_IMPLEMENTED;
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
