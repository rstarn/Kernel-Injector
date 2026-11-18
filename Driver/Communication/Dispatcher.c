#include "Dispatcher.h"

NTSTATUS DispatcherDispatch(volatile AMGER_COMMAND_HEADER* Header) {
    NTSTATUS status;

    if (Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Header->Magic != AMGER_MAGIC_NUMBER ||
        Header->Version != AMGER_PROTOCOL_VERSION) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        switch (Header->Command) {
        case AMGER_COMMAND_PING:
            status = STATUS_SUCCESS;
            break;
        case AMGER_COMMAND_INJECT:
        case AMGER_COMMAND_EJECT:
        case AMGER_COMMAND_STATUS:
            status = STATUS_NOT_IMPLEMENTED;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    Header->Status = (uint32_t)status;
    return status;
}
