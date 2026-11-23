#ifndef AMGER_LOOKUP_H
#define AMGER_LOOKUP_H

/*
 * Lookup.h - passive module, ApiSet and export lookup for Phase 4.
 *
 * Contract: reads the target's PEB, loader list and ApiSet namespace without
 * ever writing them. Every user-mode read is bounds-checked and guarded by SEH.
 * No module is inserted into the loader list, no NT API is called in user mode,
 * and no loaded module is patched. All offsets are x64 and documented in the
 * phase plan; a layout mismatch fails clean instead of guessing.
 */

#include <wdm.h>
#include "../../../Shared/Protocol.h"
#include "../../Utilities/Parser/Format.h"
#include "../Reserve/Allocate.h"

#define AMGER_PEB_LDR_OFFSET           0x018u
#define AMGER_PEB_APISET_OFFSET        0x068u
#define AMGER_PEB_LDR_LOAD_ORDER_OFFSET 0x010u
#define AMGER_LDR_DLLBASE_OFFSET       0x030u
#define AMGER_LDR_SIZEOFIMAGE_OFFSET   0x040u
#define AMGER_LDR_BASEDLLNAME_OFFSET   0x058u

#define AMGER_LOOKUP_MAX_NAME    128u
#define AMGER_LOOKUP_MAX_SYMBOL  256u
#define AMGER_LOOKUP_MAX_MODULES 128u
#define AMGER_LOOKUP_MAX_LIST    512u

typedef struct _AMGER_LOOKUP_CONTEXT {
    uint64_t Peb;
    uint64_t LdrHead;
    uint64_t ApiSetMap;
} AMGER_LOOKUP_CONTEXT, * PAMGER_LOOKUP_CONTEXT;

typedef struct _AMGER_EXPORT_RESULT {
    uint64_t Address;
    BOOLEAN Forwarded;
    BOOLEAN ByOrdinal;
    uint16_t Ordinal;
    char Module[AMGER_LOOKUP_MAX_NAME];
    char Symbol[AMGER_LOOKUP_MAX_SYMBOL];
} AMGER_EXPORT_RESULT, * PAMGER_EXPORT_RESULT;

NTKERNELAPI NTSTATUS ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

/* Called once while attached to the target process. */
NTSTATUS LookupInitialize(AMGER_LOOKUP_CONTEXT* Out);

/* Resolves api-ms-win/ext-ms-win names through PEB->ApiSetMap v6/v4/v2.
 * Sets Redirected when the name was actually rewritten. */
NTSTATUS LookupResolveApiSet(
    const AMGER_LOOKUP_CONTEXT* Context,
    const char* AnsiName,
    WCHAR* OutHost,
    SIZE_T OutCapacity,
    uint32_t* OutLength,
    BOOLEAN* OutRedirected);

/* Case-insensitive Unicode lookup across private table and PEB loader list. */
BOOLEAN LookupFindModule(
    const AMGER_LOOKUP_CONTEXT* Context,
    const WCHAR* Name,
    uint32_t NameLength,
    uint64_t* OutBase,
    uint32_t* OutSize);

/* Name or ordinal export lookup; forwarders are returned as strings. */
NTSTATUS LookupGetExport(
    uint64_t ModuleBase,
    uint32_t ModuleSize,
    const char* Name,
    uint16_t Ordinal,
    BOOLEAN ByOrdinal,
    AMGER_EXPORT_RESULT* Out);

/* Private table used by Phase 5 dependency mapping; never touches the PEB. */
VOID LookupResetPrivate(VOID);
BOOLEAN LookupRegisterPrivate(
    const WCHAR* Name,
    uint32_t NameLength,
    uint64_t Base,
    uint32_t Size);

#endif /* AMGER_LOOKUP_H */
