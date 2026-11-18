#include "Guard.h"

NTSTATUS GuardExecute(
    AMGER_EXCEPTION_GUARDED_WORKER Worker,
    PVOID Context) {
    if (Worker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        return Worker(Context);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}
