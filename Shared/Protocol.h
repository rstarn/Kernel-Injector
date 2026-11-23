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

/* Opaque mixing constant. Deliberately not an ASCII pattern (the previous
 * value spelled a four-letter tag in little-endian bytes); it only separates
 * the derived command magic from the raw machine hash. */
#define AMGER_MAGIC_NUMBER 0x7C1E9A43u

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
#define AMGER_OPTION_KNOWN_MASK (AMGER_OPTION_PROCESS_PROTECTION_MODE | \
                                 AMGER_OPTION_VIRTUAL_MACHINE_PROTECT_WAIT | \
                                 AMGER_OPTION_HEADER_ERASURE)

/* Payload bytes start immediately after the fixed header in the region. */
#define AMGER_PAYLOAD_OFFSET AMGER_COMMAND_HEADER_SIZE

/* Dispatcher log identifiers, one per validation/execution stage. */
#define AMGER_LOG_ID_HEADER_VALIDATE   1u
#define AMGER_LOG_ID_COMMAND_DECODE    2u
#define AMGER_LOG_ID_PAYLOAD_RANGE     3u
#define AMGER_LOG_ID_PING              4u
#define AMGER_LOG_ID_INJECT            5u
#define AMGER_LOG_ID_EJECT             6u
#define AMGER_LOG_ID_STATUS_COMMAND    7u
#define AMGER_LOG_ID_RESULT            8u
#define AMGER_LOG_ID_REGISTER_MDL      9u
#define AMGER_LOG_ID_REGISTER_COMMIT  10u
#define AMGER_LOG_ID_CLEANUP_DRAIN    11u
#define AMGER_LOG_ID_CLOSE_RECLAIM    12u
#define AMGER_LOG_ID_UNLOAD_OWNER     13u
#define AMGER_LOG_ID_SNAPSHOT_RETRY   14u
#define AMGER_LOG_ID_PAYLOAD_IMAGE    15u
#define AMGER_LOG_ID_INJECT_PROCESS   16u
#define AMGER_LOG_ID_INJECT_MAPPING   17u
#define AMGER_LOG_ID_INJECT_THREAD    18u

/* Reserved[0..3] is the seqlock; Reserved[8..15] carries a 64-bit result
 * value written by the driver (e.g. the injected module base). The four
 * bytes before it are alignment padding. */

typedef struct _AMGER_RESULT_CONTROL {
    uint32_t Sequence;
    uint64_t ResultValue;
    uint8_t Remainder[48];
} AMGER_RESULT_CONTROL, * PAMGER_RESULT_CONTROL;

/* Parser report lives in a dedicated area ahead of the log tail. The driver
 * fills it from the parsed descriptor; the client renders it as text. No
 * string literal is emitted by the driver. */
#define AMGER_PARSER_REPORT_SIGNATURE 0x50415253u
#define AMGER_REPORT_AREA_SIZE        2048u
#define AMGER_REPORT_MAX_MODULES      16u
#define AMGER_REPORT_NAME_LENGTH      32u

#define AMGER_REPORT_FLAG_LOAD_CONFIG   0x00000001u
#define AMGER_REPORT_FLAG_TLS           0x00000002u
#define AMGER_REPORT_FLAG_DEBUG         0x00000004u
#define AMGER_REPORT_FLAG_RESOURCE      0x00000008u
#define AMGER_REPORT_FLAG_RELOCATIONS   0x00000010u
#define AMGER_REPORT_FLAG_EXCEPTIONS    0x00000020u
#define AMGER_REPORT_FLAG_BOUND_IMPORTS 0x00000040u
#define AMGER_REPORT_FLAG_IAT           0x00000080u
#define AMGER_REPORT_FLAG_MANIFEST      0x00000100u
#define AMGER_REPORT_FLAG_CFG           0x00000200u
#define AMGER_REPORT_FLAG_CET_COMPAT    0x00000400u
#define AMGER_REPORT_FLAG_CET           0x00000800u

#define AMGER_ALLOC_FLAG_RESERVED   0x00000001u
#define AMGER_ALLOC_FLAG_RELEASED   0x00000002u

typedef struct _AMGER_ALLOC_REPORT {
    uint32_t Status;
    uint32_t TargetProcessId;
    uint32_t ImageSize;
    uint32_t Flags;
    uint64_t RemoteBase;
} AMGER_ALLOC_REPORT, * PAMGER_ALLOC_REPORT;

#define AMGER_MAP_FLAG_COMMITTED   0x00000001u
#define AMGER_MAP_FLAG_COPIED      0x00000002u
#define AMGER_MAP_FLAG_PROTECTED   0x00000004u
#define AMGER_MAP_FLAG_REVERTED    0x00000008u

/* FailureStage names the exact pass that produced Status. It lets the client
 * explain a zero PageGroups value instead of guessing which call failed. */
#define AMGER_MAP_STAGE_NONE        0u
#define AMGER_MAP_STAGE_PARAMETERS  1u
#define AMGER_MAP_STAGE_PROCESS     2u
#define AMGER_MAP_STAGE_COMMIT      3u
#define AMGER_MAP_STAGE_MDL         4u
#define AMGER_MAP_STAGE_COPY        5u
#define AMGER_MAP_STAGE_PROTECT     6u

typedef struct _AMGER_MAP_REPORT {
    uint32_t Status;
    uint32_t ImageSize;
    uint32_t BytesCopied;
    uint32_t ZeroFilled;
    uint32_t HeaderBytes;
    uint32_t PageGroups;
    uint32_t Flags;
    uint32_t FailureStage;
    uint16_t SectionCount;
    uint16_t Reserved;
    uint64_t RemoteBase;
} AMGER_MAP_REPORT, * PAMGER_MAP_REPORT;

#define AMGER_RELOC_FLAG_APPLIED    0x00000001u
#define AMGER_RELOC_FLAG_REVERTED   0x00000002u

#define AMGER_RELOC_STAGE_NONE      0u
#define AMGER_RELOC_STAGE_PARAMETERS 1u
#define AMGER_RELOC_STAGE_PROCESS   2u
#define AMGER_RELOC_STAGE_MDL       3u
#define AMGER_RELOC_STAGE_DIRECTORY 4u
#define AMGER_RELOC_STAGE_BLOCK     5u
#define AMGER_RELOC_STAGE_ENTRY     6u

typedef struct _AMGER_RELOC_REPORT {
    uint32_t Status;
    uint32_t FailureStage;
    uint32_t RelocRva;
    uint32_t RelocSize;
    uint32_t BlockCount;
    uint32_t FixupCount;
    uint32_t Dir64Count;
    uint32_t HighLowCount;
    uint32_t SkippedCount;
    uint32_t Flags;
    uint64_t Delta;
    uint64_t RemoteBase;
} AMGER_RELOC_REPORT, * PAMGER_RELOC_REPORT;

typedef struct _AMGER_PARSER_REPORT {
    uint32_t Signature;
    uint32_t ParseStatus;
    uint16_t SectionCount;
    uint16_t DirectoryCount;
    uint32_t EntryPoint;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint64_t ImageBase;
    uint32_t PeOffset;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint16_t FileCharacteristics;
    uint32_t SecurityCookieRva;
    uint32_t GuardFlags;
    uint32_t RelocDir64Count;
    uint32_t RelocHighLowCount;
    uint32_t ImportModuleCount;
    uint32_t DelayImportCount;
    uint32_t ExportCount;
    uint32_t ForwardedCount;
    uint32_t TlsCallbackCount;
    uint32_t ApiSetCount;
    uint32_t OrdinalImportCount;
    uint32_t Flags;
    AMGER_ALLOC_REPORT Allocation;
    AMGER_MAP_REPORT Mapping;
    AMGER_RELOC_REPORT Relocation;
    char ImportNames[AMGER_REPORT_MAX_MODULES][AMGER_REPORT_NAME_LENGTH];
    char ExportNames[AMGER_REPORT_MAX_MODULES][AMGER_REPORT_NAME_LENGTH];
} AMGER_PARSER_REPORT, * PAMGER_PARSER_REPORT;

/* Reserved[0..3] is the seqlock. The log ring lives in a dedicated tail area
 * at the end of the registered region, so it cannot be overwritten by payload
 * bytes and holds enough records for several commands at once. */
#define AMGER_LOG_AREA_SIZE    256u
#define AMGER_LOG_ENTRY_COUNT  15u

/* X-macro tables. Both the kernel and client generate their own lookup from
 * these, so a status is always rendered from the value actually returned. */
#define AMGER_STATUS_TABLE(X)                                    \
    X(0x00000000u, STATUS_SUCCESS)                               \
    X(0x00000102u, STATUS_TIMEOUT)                               \
    X(0x80000011u, STATUS_DEVICE_BUSY)                           \
    X(0xC0000001u, STATUS_UNSUCCESSFUL)                          \
    X(0xC0000002u, STATUS_NOT_IMPLEMENTED)                       \
    X(0xC0000005u, STATUS_ACCESS_VIOLATION)                      \
    X(0xC000000Du, STATUS_INVALID_PARAMETER)                     \
    X(0xC0000010u, STATUS_INVALID_DEVICE_REQUEST)                \
    X(0xC0000018u, STATUS_CONFLICTING_ADDRESSES)                 \
    X(0xC0000022u, STATUS_ACCESS_DENIED)                         \
    X(0xC0000034u, STATUS_OBJECT_NAME_NOT_FOUND)                 \
    X(0xC000009Au, STATUS_INSUFFICIENT_RESOURCES)                \
    X(0xC0000184u, STATUS_INVALID_DEVICE_STATE)                  \
    X(0xC000022Du, STATUS_RETRY)

#define AMGER_LOG_ID_TABLE(X)                                    \
    X(AMGER_LOG_ID_HEADER_VALIDATE,  HEADER_VALIDATE)             \
    X(AMGER_LOG_ID_COMMAND_DECODE,   COMMAND_DECODE)              \
    X(AMGER_LOG_ID_PAYLOAD_RANGE,    PAYLOAD_RANGE)               \
    X(AMGER_LOG_ID_PING,             PING)                        \
    X(AMGER_LOG_ID_INJECT,           INJECT)                      \
    X(AMGER_LOG_ID_EJECT,            EJECT)                       \
    X(AMGER_LOG_ID_STATUS_COMMAND,   STATUS_COMMAND)              \
    X(AMGER_LOG_ID_RESULT,           RESULT)                      \
    X(AMGER_LOG_ID_REGISTER_MDL,     REGISTER_MDL)                \
    X(AMGER_LOG_ID_REGISTER_COMMIT,  REGISTER_COMMIT)             \
    X(AMGER_LOG_ID_CLEANUP_DRAIN,    CLEANUP_DRAIN)               \
    X(AMGER_LOG_ID_CLOSE_RECLAIM,    CLOSE_RECLAIM)               \
    X(AMGER_LOG_ID_UNLOAD_OWNER,     UNLOAD_OWNER)                \
    X(AMGER_LOG_ID_SNAPSHOT_RETRY,   SNAPSHOT_RETRY)                 \
    X(AMGER_LOG_ID_PAYLOAD_IMAGE,    PAYLOAD_IMAGE)                  \
    X(AMGER_LOG_ID_INJECT_PROCESS,   INJECT_PROCESS)                 \
    X(AMGER_LOG_ID_INJECT_MAPPING,   INJECT_MAPPING)                 \
    X(AMGER_LOG_ID_INJECT_THREAD,    INJECT_THREAD)

/* Maximum payload capacity reserved by the protocol for future work. */
#define AMGER_MAXIMUM_PAYLOAD_SIZE (64u * 1024u * 1024u)

/* Fixed command header and maximum registration capacity. */
#define AMGER_COMMAND_HEADER_SIZE 128u
#define AMGER_SHARED_REGION_SIZE (AMGER_COMMAND_HEADER_SIZE + AMGER_MAXIMUM_PAYLOAD_SIZE)

/* Baseline region size for commands that carry no payload. */
#define AMGER_COMMAND_REGION_SIZE AMGER_COMMAND_HEADER_SIZE

/* Every registered region carries the command header and the log tail. */
#define AMGER_MINIMUM_REGION_SIZE \
    (AMGER_COMMAND_HEADER_SIZE + AMGER_REPORT_AREA_SIZE + AMGER_LOG_AREA_SIZE)

/* Seqlock fields inside AMGER_COMMAND_HEADER.Reserved. */
#define AMGER_SEQUENCE_OFFSET 48u
#define AMGER_SEQUENCE_RETRY_LIMIT 4u

/* Every externally visible identifier is derived from the machine GUID.
 * There is no product string in any device name. The two sides compute the
 * same values from the same registry value; a failed read falls back to a
 * derived constant so both still agree. */
#define AMGER_NAME_DIGITS 16u

/* Neutral fallback when the MachineGuid registry value is unreadable. Both
 * sides derive from the same text, so the value only has to be identical —
 * it must not carry any product identifier. */
#define AMGER_FALLBACK_GUID L"6F1D9A24-8C3E-4B57-A0D2-9E8F1C4A6B30"

/* FNV-1a 64 over UTF-16 code units, in C so both C and C++ can use it. */

static __inline uint64_t AmgerMachineHash(const wchar_t* text, size_t length) {
    uint64_t hash = 14695981039346656037ull;
    for (size_t index = 0u; index < length; ++index) {
        const uint16_t unit = (uint16_t)text[index];
        hash ^= (uint64_t)(unit & 0xFFu);
        hash *= 1099511628211ull;
        hash ^= (uint64_t)(unit >> 8);
        hash *= 1099511628211ull;
    }
    return hash;
}

/* Minimum destination capacity for AmgerAppendName: the bytes already written
 * (the prefix), the AMGER_NAME_DIGITS hex digits it appends, and the trailing
 * NUL. Every caller must guarantee at least this much room; call sites assert
 * it at compile time. */
#define AMGER_APPEND_NAME_CAPACITY(prefix_length) \
    ((prefix_length) + AMGER_NAME_DIGITS + 1u)

/* Assert a destination buffer has room for a prefix of prefix_length wchar_t,
 * the appended digits, and the NUL. Widen wcslen(prefix) as the caller's
 * compile-time constant (e.g. the literal length, not a runtime value). */
#define AMGER_ASSERT_NAME_BUFFER(buffer_elems, prefix_length) \
    AMGER_STATIC_ASSERT((buffer_elems) >= AMGER_APPEND_NAME_CAPACITY(prefix_length), \
                        "name buffer too small for prefix + digits + NUL")

/* Appends sixteen hex digits to an already-populated namespace prefix.
 * `capacity` is the total buffer size in wchar_t; the function never writes
 * past it, but a buffer smaller than AMGER_APPEND_NAME_CAPACITY would truncate
 * the name and break agreement between the two sides. */

static __inline void AmgerAppendName(wchar_t* buffer, size_t capacity, uint64_t value) {
    static const wchar_t digits[] = L"0123456789ABCDEF";
    size_t used = 0u;
    while (used < capacity && buffer[used] != L'\0') {
        ++used;
    }
    for (int shift = 60; shift >= 0; shift -= 4) {
        if (used + 1u < capacity) {
            buffer[used++] = digits[(value >> shift) & 0xFu];
        }
    }
    if (used < capacity) {
        buffer[used] = L'\0';
    }
}

/* Per-machine IOCTL function offsets and magic value. */

static __inline uint32_t AmgerIoctlFunction(uint32_t base, uint64_t hash) {
    return base + (uint32_t)(hash & 0x7Fu);
}

static __inline uint32_t AmgerMagicValue(uint64_t hash) {
    return (uint32_t)(hash ^ (hash >> 32)) ^ AMGER_MAGIC_NUMBER;
}

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
#define AMGER_IOCTL_FUNCTION_UNLOAD   0x802u
#define AMGER_IOCTL_METHOD            0u
#define AMGER_IOCTL_ACCESS            0x0002u

/*
 * The PING command is issued through AMGER_IOCTL_KICK with AMGER_COMMAND_PING
 * in the shared header; there is no dedicated PING IOCTL.
 */
#define AMGER_IOCTL_REGISTER_SHARED_REGION \
    CTL_CODE(AMGER_DEVICE_TYPE, AMGER_IOCTL_FUNCTION_REGISTER, AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS)
#define AMGER_IOCTL_KICK \
    CTL_CODE(AMGER_DEVICE_TYPE, AMGER_IOCTL_FUNCTION_KICK, AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS)
#define AMGER_IOCTL_UNLOAD \
    CTL_CODE(AMGER_DEVICE_TYPE, AMGER_IOCTL_FUNCTION_UNLOAD, AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS)

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

/* One dispatcher log record. Sequence is absolute so the client can display
 * only entries newer than the last one it saw. */

typedef struct _AMGER_LOG_ENTRY {
    uint32_t Sequence;
    uint16_t Id;
    uint16_t Reserved;
    uint32_t Status;
    uint32_t Detail;
} AMGER_LOG_ENTRY, * PAMGER_LOG_ENTRY;

typedef struct _AMGER_LOG_RING {
    uint32_t Sequence;
    AMGER_LOG_ENTRY Entries[AMGER_LOG_ENTRY_COUNT];
} AMGER_LOG_RING, * PAMGER_LOG_RING;

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
AMGER_STATIC_ASSERT(sizeof(AMGER_RESULT_CONTROL) == 64,
                    "AMGER_RESULT_CONTROL must cover Reserved exactly");
AMGER_STATIC_ASSERT(sizeof(AMGER_PARSER_REPORT) <= AMGER_REPORT_AREA_SIZE,
                    "parser report must fit the report area");
AMGER_STATIC_ASSERT(offsetof(AMGER_PARSER_REPORT, Signature) == 0u,
                    "parser report signature offset mismatch");
AMGER_STATIC_ASSERT(sizeof(AMGER_SHARED_REGION_REQUEST) == 16,
                    "AMGER_SHARED_REGION_REQUEST must be 16 bytes");
AMGER_STATIC_ASSERT(sizeof(AMGER_LOG_ENTRY) == 16,
                    "AMGER_LOG_ENTRY must be 16 bytes");
AMGER_STATIC_ASSERT(sizeof(AMGER_LOG_RING) == 244,
                    "AMGER_LOG_RING must be 244 bytes");
AMGER_STATIC_ASSERT(sizeof(AMGER_LOG_RING) <= AMGER_LOG_AREA_SIZE,
                    "log ring must fit inside the log area");
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

/* IOCTL values are derived per machine at runtime, so only their spacing is
 * fixed here. */

AMGER_STATIC_ASSERT(AMGER_IOCTL_FUNCTION_KICK - AMGER_IOCTL_FUNCTION_REGISTER == 1u,
                    "IOCTL function spacing mismatch");
AMGER_STATIC_ASSERT(AMGER_IOCTL_FUNCTION_UNLOAD - AMGER_IOCTL_FUNCTION_KICK == 1u,
                    "IOCTL function spacing mismatch");

#endif /* AMGER_PROTOCOL_H */
