#include "Dispatcher.h"

NTSTATUS DispatcherDispatch(
    const AMGER_COMMAND_SNAPSHOT* Snapshot,
    uint32_t* OutStatus) {
    NTSTATUS status;

    if (OutStatus == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Snapshot == NULL) {
        status = STATUS_INVALID_PARAMETER;
    } else if (Snapshot->Magic != AMGER_MAGIC_NUMBER ||
               Snapshot->Version != AMGER_PROTOCOL_VERSION) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        switch (Snapshot->Command) {
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

    *OutStatus = (uint32_t)status;
    return status;
}
