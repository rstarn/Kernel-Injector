#ifndef AMGER_PROTOCOL_H
#define AMGER_PROTOCOL_H

/*
 * Protocol.h - wire contract between Loader.exe and InjectorDriver.sys.
 *
 * Contract: fixed-layout, C-compatible declarations included by both the
 * kernel driver (.c) and the user-mode loader (.cpp). No SDK headers are
 * included here; only compiler-provided fixed-width integer types are used so
 * the same byte layout is produced in both translation-unit kinds.
 *
 * Inputs: none.
 * Outputs: command header, request structure, IOCTL codes, limits, paths.
 * Failure modes: a mismatched sizeof(AMGER_COMMAND_HEADER) in either side
 * breaks all command delivery; both sides assert the 128-byte size at build
 * time through their own compile-time checks.
 */

#include <stdint.h>

/*
 * Magic value 'AMGR' placed in every command header. A driver receiving a
 * header without this value must not act on the Command field.
 */
#define AMGER_MAGIC_NUMBER 0x52474D41u

/* Protocol revision. Both sides must agree or the command is refused. */
#define AMGER_PROTOCOL_VERSION 1u

/* Command identifiers carried in AMGER_COMMAND_HEADER.Command. */
#define AMGER_COMMAND_PING   1u
#define AMGER_COMMAND_INJECT 2u
#define AMGER_COMMAND_EJECT  3u
#define AMGER_COMMAND_STATUS 4u

/* Bit flags carried in AMGER_COMMAND_HEADER.Options. */
#define AMGER_OPTION_PROCESS_PROTECTION_MODE   0x00000001u
#define AMGER_OPTION_VIRTUAL_MACHINE_PROTECT_WAIT 0x00000002u
#define AMGER_OPTION_HEADER_ERASURE            0x00000004u

/* Largest payload the shared region will ever carry: 64 MB. */
#define AMGER_MAXIMUM_PAYLOAD_SIZE (64u * 1024u * 1024u)

/* Size of the fixed command header at the head of the shared region. */
#define AMGER_COMMAND_HEADER_SIZE 128u

/* Total size of the region the loader allocates and the driver locks. */
#define AMGER_SHARED_REGION_SIZE (AMGER_COMMAND_HEADER_SIZE + AMGER_MAXIMUM_PAYLOAD_SIZE)

/* Default bootstrap file path; the loader expands the environment variable. */
#define AMGER_BOOTSTRAP_PATH L"%TEMP%\\AmegerBootstrap.txt"

/* Kernel object name prefixes. The GUID hex suffix is 32 characters. */
#define AMGER_DEVICE_NAME_PREFIX       L"\\Device\\AmgerGUID"
#define AMGER_SYMBOLIC_LINK_PREFIX     L"\\DosDevices\\AmgerGUID"
#define AMGER_USER_DEVICE_PREFIX       L"\\\\.\\AmgerGUID"
#define AMGER_GUID_HEX_LENGTH          32u

/*
 * IOCTL values, equivalent to CTL_CODE(FILE_DEVICE_UNKNOWN, function,
 * METHOD_BUFFERED, FILE_ANY_ACCESS) with functions 0x800 and 0x801.
 * Kept as literals so neither side needs devioctl.h or winioctl.h.
 */
#define AMGER_IOCTL_REGISTER_SHARED_REGION 0x00222000u
#define AMGER_IOCTL_KICK                   0x00222004u

/*
 * AMGER_COMMAND_HEADER - the fixed 128-byte command slot.
 *
 * Contract: the driver writes Status; the loader writes every other field.
 * Inputs: Magic, Version, Command, PayloadVirtualAddress, PayloadSize,
 * TargetProcessId, Options, CompletionEventHandle are supplied by the loader.
 * Outputs: Status is the NTSTATUS produced by the driver's dispatcher.
 * Failure modes: an outside observer can modify the region because it is
 * mapped writable in the loader; no authentication is provided in Phase 1.
 *
 * AlignmentPadding exists solely to bring the structure to exactly 128 bytes
 * on both x64 compilers; it must remain zero.
 */
typedef struct _AMGER_COMMAND_HEADER {
    uint32_t Magic;
    uint32_t Version;
    uint32_t Command;
    uint32_t Status;
    uint64_t PayloadVirtualAddress;
    uint64_t PayloadSize;
    uint32_t TargetProcessId;
    uint32_t Options;
    uint64_t CompletionEventHandle;
    uint8_t  Reserved[64];
    uint8_t  AlignmentPadding[16];
} AMGER_COMMAND_HEADER, * PAMGER_COMMAND_HEADER;

/*
 * AMGER_SHARED_REGION_REQUEST - payload of IOCTL_REGISTER_SHARED_REGION.
 *
 * Contract: describes the user-mode region to be locked and mapped.
 * Inputs: VirtualAddress is the base of a MEM_COMMIT allocation in the
 * calling process; Size must be <= AMGER_SHARED_REGION_SIZE.
 * Outputs: none; success is the IOCTL completion status.
 * Failure modes: an invalid VirtualAddress or Size is rejected with
 * STATUS_INVALID_PARAMETER; an unmapped address surfaces as
 * STATUS_ACCESS_VIOLATION from the driver's exception guard.
 */
typedef struct _AMGER_SHARED_REGION_REQUEST {
    uint64_t VirtualAddress;
    uint64_t Size;
} AMGER_SHARED_REGION_REQUEST, * PAMGER_SHARED_REGION_REQUEST;

#endif /* AMGER_PROTOCOL_H */
