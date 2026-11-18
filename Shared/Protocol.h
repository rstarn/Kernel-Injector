#ifndef AMGER_PROTOCOL_H
#define AMGER_PROTOCOL_H

/*
 * Protocol.h - wire contract between Client.exe and Driver.sys.
 *
 * Contract: fixed-layout, C-compatible declarations included by both the
 * kernel driver (.c) and the user-mode client (.cpp). No SDK headers are
 * included here; compiler-provided fixed-width integer types are used so the
 * same byte layout is produced in both translation-unit kinds.
 *
 * Inputs: none.
 * Outputs: command header, request structure, IOCTL codes, limits, paths.
 * Failure modes: a mismatched layout in either side breaks command delivery;
 * compile-time assertions below prove the layout and IOCTL values agree.
 *
 * AMGER_STATUS_PENDING is the client-written sentinel in Header.Status. Zero
 * is STATUS_SUCCESS and therefore never an in-progress value. The driver must
 * overwrite the sentinel on every execution path.
 *
 * Header.Reserved[0..3] is a seqlock-style Sequence counter. The writer makes
 * it odd before updating the command fields and even afterwards. The driver
 * captures a kernel-local snapshot and rejects an inconsistent observation.
 * This detects accidental concurrent updates by a cooperating client. It does
 * NOT defend against a malicious user-mode writer that deliberately forges an
 * even sequence while changing fields; payloads are still attacker-controlled.
 */

#include <stddef.h>
#include <stdint.h>

#define AMGER_MAGIC_NUMBER 0x52474D41u

/* Version 2 adds the sequence-counter snapshot protocol. */
#define AMGER_PROTOCOL_VERSION 2u

/* Never used by the driver as a final status. */
#define AMGER_STATUS_PENDING 0xFFFFFFFFu

/* Command identifiers carried in AMGER_COMMAND_HEADER.Command. */
#define AMGER_COMMAND_PING   1u
#define AMGER_COMMAND_INJECT 2u
#define AMGER_COMMAND_EJECT  3u
#define AMGER_COMMAND_STATUS 4u

/* Bit flags carried in AMGER_COMMAND_HEADER.Options. */
#define AMGER_OPTION_PROCESS_PROTECTION_MODE      0x00000001u
#define AMGER_OPTION_VIRTUAL_MACHINE_PROTECT_WAIT 0x00000002u
#define AMGER_OPTION_HEADER_ERASURE               0x00000004u

/* Maximum payload capacity reserved by the protocol for future work. */
#define AMGER_MAXIMUM_PAYLOAD_SIZE (64u * 1024u * 1024u)

/* Fixed command header and maximum registration capacity. */
#define AMGER_COMMAND_HEADER_SIZE 128u
#define AMGER_SHARED_REGION_SIZE (AMGER_COMMAND_HEADER_SIZE + AMGER_MAXIMUM_PAYLOAD_SIZE)

/* Region size used by the currently implemented PING-only commands. */
#define AMGER_COMMAND_REGION_SIZE AMGER_COMMAND_HEADER_SIZE

/* Seqlock fields inside AMGER_COMMAND_HEADER.Reserved. */
#define AMGER_SEQUENCE_OFFSET 48u
#define AMGER_SEQUENCE_RETRY_LIMIT 4u

/* Bootstrap discovery path; both sides resolve to the system temp directory. */
#define AMGER_BOOTSTRAP_PATH L"%SystemRoot%\\Temp\\AmegerBootstrap.txt"

/* Kernel object name prefixes. The GUID hex suffix is 32 characters. */
#define AMGER_DEVICE_NAME_PREFIX   L"\\Device\\AmgerGUID"
#define AMGER_SYMBOLIC_LINK_PREFIX L"\\DosDevices\\AmgerGUID"
#define AMGER_USER_DEVICE_PREFIX   L"\\\\.\\AmgerGUID"
#define AMGER_GUID_HEX_LENGTH      32u

/*
 * CTL_CODE definition, written locally so neither compilation environment
 * needs devioctl.h. FILE_DEVICE_UNKNOWN + METHOD_BUFFERED + FILE_WRITE_ACCESS.
 */
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#define AMGER_DEVICE_TYPE             0x00000022u
#define AMGER_IOCTL_FUNCTION_REGISTER 0x800u
#define AMGER_IOCTL_FUNCTION_KICK     0x801u
#define AMGER_IOCTL_METHOD            0u
#define AMGER_IOCTL_ACCESS            0x0002u

#define AMGER_IOCTL_REGISTER_SHARED_REGION \
    CTL_CODE(AMGER_DEVICE_TYPE, AMGER_IOCTL_FUNCTION_REGISTER, AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS)
#define AMGER_IOCTL_KICK \
    CTL_CODE(AMGER_DEVICE_TYPE, AMGER_IOCTL_FUNCTION_KICK, AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS)

/*
 * AMGER_COMMAND_HEADER - the fixed 128-byte command slot.
 *
 * Contract: the driver writes Status and Sequence; the client writes the
 * command fields and Sequence. AlignmentPadding exists only to reach 128
 * bytes and must remain zero.
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

/* Overlay for the seqlock word inside Reserved. */
typedef struct _AMGER_HEADER_CONTROL {
    uint32_t Sequence;
    uint8_t  Remainder[60];
} AMGER_HEADER_CONTROL, * PAMGER_HEADER_CONTROL;

/*
 * AMGER_COMMAND_SNAPSHOT - kernel-local copy of the command input.
 * Not part of the wire layout; used so dispatch never reads mutable user memory.
 */
typedef struct _AMGER_COMMAND_SNAPSHOT {
    uint32_t Magic;
    uint32_t Version;
    uint32_t Command;
    uint32_t Status;
    uint64_t PayloadVirtualAddress;
    uint64_t PayloadSize;
    uint32_t TargetProcessId;
    uint32_t Options;
    uint64_t CompletionEventHandle;
} AMGER_COMMAND_SNAPSHOT, * PAMGER_COMMAND_SNAPSHOT;

/*
 * AMGER_SHARED_REGION_REQUEST - payload of IOCTL_REGISTER_SHARED_REGION.
 *
 * Contract: describes the user-mode region to be locked and mapped. Size must
 * be at least the header size and no greater than AMGER_SHARED_REGION_SIZE.
 */
typedef struct _AMGER_SHARED_REGION_REQUEST {
    uint64_t VirtualAddress;
    uint64_t Size;
} AMGER_SHARED_REGION_REQUEST, * PAMGER_SHARED_REGION_REQUEST;

#ifdef __cplusplus
#define AMGER_STATIC_ASSERT(expression, message) static_assert(expression, message)
#else
#define AMGER_STATIC_ASSERT(expression, message) \
    typedef char __amger_static_assert_line_##__LINE__[(expression) ? 1 : -1]
#endif

AMGER_STATIC_ASSERT(sizeof(AMGER_COMMAND_HEADER) == 128,
                    "AMGER_COMMAND_HEADER must be 128 bytes");
AMGER_STATIC_ASSERT(sizeof(AMGER_HEADER_CONTROL) == 64,
                    "AMGER_HEADER_CONTROL must cover Reserved exactly");
AMGER_STATIC_ASSERT(sizeof(AMGER_SHARED_REGION_REQUEST) == 16,
                    "AMGER_SHARED_REGION_REQUEST must be 16 bytes");
AMGER_STATIC_ASSERT(offsetof(AMGER_COMMAND_HEADER, Magic) == 0,
                    "Magic offset mismatch");
AMGER_STATIC_ASSERT(offsetof(AMGER_COMMAND_HEADER, Version) == 4,
                    "Version offset mismatch");
AMGER_STATIC_ASSERT(offsetof(AMGER_COMMAND_HEADER, Command) == 8,
                    "Command offset mismatch");
AMGER_STATIC_ASSERT(offsetof(AMGER_COMMAND_HEADER, Status) == 12,
                    "Status offset mismatch");
AMGER_STATIC_ASSERT(offsetof(AMGER_COMMAND_HEADER, Reserved) == AMGER_SEQUENCE_OFFSET,
                    "Sequence offset mismatch");
AMGER_STATIC_ASSERT(AMGER_SEQUENCE_OFFSET % 4u == 0u,
                    "Sequence counter must be 4-byte aligned");
AMGER_STATIC_ASSERT(offsetof(AMGER_COMMAND_HEADER, AlignmentPadding) == 112,
                    "AlignmentPadding offset mismatch");
AMGER_STATIC_ASSERT(AMGER_IOCTL_REGISTER_SHARED_REGION == 0x0022A000u,
                    "REGISTER IOCTL value mismatch");
AMGER_STATIC_ASSERT(AMGER_IOCTL_KICK == 0x0022A004u,
                    "KICK IOCTL value mismatch");

#endif /* AMGER_PROTOCOL_H */
