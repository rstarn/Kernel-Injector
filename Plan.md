### Injector: DLL Requirements:
1. TLS callbacks -- run TLS callbacks before the DLL entry point.
2. Undocumented routine resolution -- locate required ntdll loader symbols.
3. Load atomicity -- roll back any partial DLL state if a mapping step fails.
4. Forwarded exports -- follow forwarded exports recursively with a depth cap.
5. Static TLS -- allocate TLS index from PEB bitmap and init TEB slots in kernel.
6. Activation context -- activate embedded SxS manifest for dependency resolution.
7. Base relocations -- apply DIR64 / HIGHLOW fixups or fail when no .reloc exists.
8. Section mapping -- handle SectionAlignment vs FileAlignment and zero-fill .bss.
9. Bound import invalidation -- clear stale bound import data after IAT resolution.
10. API-set redirection -- resolve api-ms-win and ext-ms-win names via ApiSetSchema.
11. Section protections -- map all five protection cases from section characteristics.
12. Load-config validation -- validate GuardFlags and data-directory indices before use.
13. Configurable entry point -- support DllMain, a named export, or an ordinal as entry.
14. Delay-load imports -- resolve delay-load descriptors including ordinal and name thunks.
15. .pdata registration -- insert .pdata via kernel-side dynamic-table insertion for unwind.
16. Deep PE validator -- bounds-check every RVA, size and data directory against SizeOfImage.
17. Image allocation -- reserve SizeOfImage in the target process and return the mapped base.
18. Dependency loading -- prefer already-loaded modules; manually map missing ones in kernel.
19. CFG retarget -- point the mapped guard-call pointer to a legitimate-module return gadget.
20. Header wipe -- zero the mapped PE headers in the target process to remove signature anchors.
21. PE validation -- validate PE32+ headers, enforce x64-only and refuse architecture mismatches.
22. Imports by name/ordinal -- resolve both name and ordinal imports, including ordinal-only APIs.
23. Exception base resolution -- intercept RtlPcToFileHeader so /MT CRT throws find the mapped base.
24. Mitigation detection -- query process mitigations and gate CFG / CET behavior to what is enabled.
25. Thread TLS callbacks -- fire DLL_THREAD_ATTACH and DLL_THREAD_DETACH for payload-created threads.
26. Security cookie -- init and preserve the /GS security cookie and its complement from load config.
27. CET gate -- detect EnableUserShadowStack; if active, WTH return overwrite is fatal -- fail clean.
28. Dependency refcount + cycle tracking -- track dependency records with refcounts and handle cycles.
29. CET / shadow stack -- honor CETCOMPAT and GuardEHContinuations only when the process enforces them.
30. CRT entry point -- call _DllMainCRTStartup / _CRT_INIT with DLL_PROCESS_ATTACH, not DllMain directly.
31. Thread hijack -- overwrite [RSP] of a waiting worker thread; no suspend, no context write, fail clean.


### Injector: Architecture:

## Information:
- Fully kernel-level.
- DLL Targets: x64 only.
- Mapped with a manual mapper (D:\Ameger\Mapper)

## Method:
Injection: Manual Mapping
Execution: Thread Hijacking

## Parser

Implemented in `Driver/Utilities/Parser/Format.h` and `Format.c`. Phase 0 (R21, R16) is complete and wired into `Dispatcher.c`. Phases 1 and 2 are implemented in `Reserve/` and `Mapping/`; `InjectorExecute` orchestrates them but returns `STATUS_NOT_IMPLEMENTED` while phases 3–8 are deferred.

API:
- `PeParseAndValidate(Image, ImageSize, Out)` — returns STATUS_SUCCESS or STATUS_INVALID_PARAMETER; the descriptor is zeroed on entry.
- `PeRvaToOffset(Image, Rva, Length, OutOffset)` — maps a file-backed RVA range; fails for zero-filled virtual tails.

Descriptor (`AMGER_PE_IMAGE`): Base, Size, PeOffset, ImageBase (64-bit), SizeOfImage, SizeOfHeaders, SectionAlignment, FileAlignment, AddressOfEntryPoint, NumberOfSections (<=96), Subsystem, DllCharacteristics, FileCharacteristics, NumberOfRvaAndSizes (<=16), Directories[16], Sections[96]. Fixed arrays, stack-supplied, no pool allocation.

Validation gates, in order:
1. Size >= 0x40; e_lfanew in [0x40, Size-24].
2. PE signature; Machine == 0x8664.
3. Sections 1..96; SizeOfOptionalHeader >= 112; IMAGE_FILE_DLL set; 32BIT_MACHINE and bytes-reversed flags clear.
4. Optional header fully inside the image; Magic == 0x020B (PE32+).
5. FileAlignment 0x200..0x10000 power of two; SectionAlignment >= FileAlignment and power of two.
6. SizeOfImage >= SizeOfHeaders and <= 512 MiB; section table fits in SizeOfHeaders and in the file.
7. NumberOfRvaAndSizes <= 16; directory array fits inside the optional header.
8. Each non-empty directory: RVA + Size <= SizeOfImage; the certificate table (index 4) is a file offset and bounds-checked against file size.
9. Each section: raw range inside the file, virtual span inside SizeOfImage.
10. AddressOfEntryPoint is zero or lies in the headers or a section.

Failure model: every rejection returns STATUS_INVALID_PARAMETER. No string, no DbgPrintEx, no pool allocation. The parser runs inside KickWorker's GuardExecute SEH frame but never depends on it. Dispatcher logs PAYLOAD_IMAGE on rejection; on success it resets StageId to INJECT and calls the stub.

Integration: `Dispatcher.c` includes `Format.h` and calls `PeParseAndValidate` in the INJECT case. `Create.bat` compiles and links `Format.obj`. `Protocol.h` carries the report layout and area size; no new log IDs were needed.

Verified: a user-mode harness against `Assets\Target.dll` accepted it — 6 sections, 16 directories, entry 0x14020, image base 0x180000000, SizeOfImage 0x1062000, headers 0x400, DllCharacteristics 0x160, RVA 0x14020 -> offset 0x13420. A 64-byte zero buffer was rejected. Driver builds `/W4 /kernel` with zero warnings; Verify.bat passes.

The report now includes import/delay-import/export names and counts, forwarded and ordinal counts, ApiSet references, TLS callback count, security cookie RVA, guard flags, relocation type counts, directory presence flags and manifest detection. Table *contents* beyond those summaries remain deferred to Phase 4+.

## Allocation

R17 is implemented in `Driver/Execution/Reserve/Allocate.h` and `Allocate.c`; `Create.bat` compiles and links `Allocate.obj`. `Injector.c` remains the orchestrator in `Driver/Execution/`.

API:
- `AllocateReserveImage(HANDLE ProcessId, SIZE_T ImageSize, uint64_t* OutBase)` — reserves `SizeOfImage` and returns the user-mode base.
- `AllocateReleaseImage(HANDLE ProcessId, uint64_t Base)` — paired rollback primitive for R3.

Sequence:
1. `PsLookupProcessByProcessId` — the only process reference taken; never `OpenProcess` or `DuplicateHandle`.
2. `KeStackAttachProcess` into the target.
3. `ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &size, MEM_RESERVE, PAGE_READWRITE)` with `base = NULL` so the memory manager picks a 64 KiB-aligned region. Never request the DLL's preferred base — fixed-address patterns collide and stand out.
4. `KeUnstackDetachProcess`, then `ObDereferenceObject` on every path.
5. Publish the base through the 64-bit result channel; zero it on every failure path.

Detection-aware decisions (research-backed):
- `MEM_RESERVE` only — no `MEM_COMMIT`. ETW-TI logs executable allocations through `EtwTiLogAllocExecVm`; reserve-only RW memory stays below that threshold. Event 21 (`ALLOCVM_REMOTE_KERNEL_CALLER`) may still fire, but it is low-signal compared with commit + execute.
- `PAGE_READWRITE`, never `PAGE_EXECUTE*`, never RWX. The VAD stays non-executable until Phase 2 promotes section protections.
- Kernel-origin `Zw` under attach — no user-mode API call chain, no `WriteProcessMemory`, no `VirtualAllocEx`.
- No kernel pool allocation and no distinctive tag; descriptor and context stay on the stack.
- Warden VEH and INT3 trampolines are untouched (`.analysis`): removing them crashes the process on the next INT3.
- Driver-load artefacts (`PiDDBCacheTable`, `MmUnloadedDrivers`, `KernelHashBucketList`, `PoolBigPageTable`, WdFilter `RuntimeDrivers`, `FF 25` import-wrapper scanning, APC stack-walking for unbacked frames) are mapper-level risks already listed under Additional Mitigations. They are outside this phase.

Failure model: invalid PID, zero/oversized image, dead target or allocation failure returns a named NTSTATUS; no partial reservation survives. Release is idempotent on a zero/invalid base.

Report extension: add allocation fields to the existing `AMGER_PARSER_REPORT` in the 2048-byte area (current size 1128, room remains). Client renders a second `Allocation:` block with white labels, white separators and green/red values, exactly like the parser block:

```
Allocation:

  Status: 0x00000000 (STATUS_SUCCESS)
  Target PID: 9956
  Image Size: 0x001062000

  Remote Base: 0x0000020000000000
  Protection: READWRITE (reserve only)

  Execution: deferred to Phase 2
```

Verification order: test on `notepad` first with the client console. Until Phases 2–8 land, INJECT must still return `STATUS_NOT_IMPLEMENTED` — a successful allocation must not claim injection succeeded. Overwatch is tested only after the entire injector is finished.

## Mapping

R8 and R11 are implemented in `Driver/Execution/Mapping/Sections.h` and `Sections.c`; `Create.bat` compiles and links `Sections.obj`. `Injector.c` keeps the Phase 1 reservation alive and calls this module before any later phase.

API:
- `MapSectionsMap(CONST AMGER_PE_IMAGE* Image, HANDLE ProcessId, uint64_t RemoteBase, PAMGER_MAP_REPORT Out)` — commits, copies and applies protections.
- `MapSectionsRevert(HANDLE ProcessId, uint64_t RemoteBase, CONST AMGER_MAP_REPORT* Report)` — paired R3 rollback.

Sequence:
1. Keep the Phase 1 reservation; do not release it on the success path.
2. Commit `SizeOfImage` as `PAGE_READWRITE` at the reserved base with one kernel-origin `ZwAllocateVirtualMemory(MEM_COMMIT)` while attached. Never commit executable protection.
3. Copy `SizeOfHeaders` bytes from image offset 0 to RVA 0.
4. For each section: destination `RemoteBase + VirtualAddress`; source `Image->Base + RawOffset`; copy `min(VirtualSize, RawSize)`; zero-fill `VirtualSize - RawSize` when `VirtualSize > RawSize` (`.bss`). FileAlignment vs SectionAlignment is handled by RVA placement — a flat file copy is wrong.
5. Group section ranges by **page**, merge characteristics into one protection per page, and apply protections once. Never leave a page RWX; promote RW → RX exactly once.
6. Five protection cases from characteristics: no access -> `PAGE_NOACCESS`; execute only -> `PAGE_EXECUTE`; execute + read -> `PAGE_EXECUTE_READ`; read only -> `PAGE_READONLY`; read + write -> `PAGE_READWRITE`.
7. Header wipe (`R20`) stays in Phase 7, not here.

Detection-aware decisions (research-backed):
- ETW-TI emits `EtwTiLogProtectExecVm` when private memory becomes executable; kernel-caller PROTECTVM events exist. The immutable-code-page principle is RW -> RX once — protection fluctuation (RX -> RW, or repeated toggles) is high-signal, so each code page is promoted once and never touched again.
- Executable private memory with no file backing is the classic VAD signature scanned by EAC and BattlEye. Image-backed mapping via `ZwCreateSection(SEC_IMAGE)` is the only real PTE fix but adds a disk artifact and changes architecture — deferred, not done here.
- No CFG bitmap writes for the private range; no section names or brand strings emitted; descriptor and report stay on the stack; copies go through the MDL-locked system mapping.

Failure model: invalid descriptor, dead target, failed commit, out-of-range RVA or protection failure returns a named NTSTATUS. The undo log records the committed range and applied protections; rollback releases the reservation. No partially mapped image survives.

Report extension: add `AMGER_MAP_REPORT` (Status, RemoteBase, ImageSize, SectionCount, BytesCopied, ZeroFilled, HeaderBytes, PageGroups, Flags) to the existing report area. Client renders a `Mapping:` block in the same white-label/green-red style:

```
Mapping:

  Status: 0x00000000 (STATUS_SUCCESS)

  Remote Base: 0x0000000056000000
  Image Size: 0x00C87A00
  Sections: 6

  Bytes Copied: 0x00C00000
  Zero Filled: 0x00004A00
  Headers: 0x00000400

  Protections: applied (no RWX)
  Page Groups: 18
  Commit: read/write

  Rollback: mapping reverted
  Execution: deferred to Phase 3
```

Verification order: test on `notepad` first. INJECT must still return `STATUS_NOT_IMPLEMENTED`; the `Mapping:` block is the proof. Confirm with WinDbg `!vad` that the region is private and non-executable before promotion, then executable after. Overwatch is tested only after the entire injector is finished.

# Injection: Manual Mapping

Phase-ordered pipeline. Each requirement appears once, by number; the numbered list above is the inventory, this table is the design. Every phase is an abort point.

| Phase | Name | Requirements |
|---|---|---|
| 0 | Prepare | R2, R21, R16 |
| 1 | Allocate | R17 |
| 2 | Map sections | R8, R11 |
| 3 | Relocate | R7 |
| 4 | Imports | R10, R22, R4, R14, R9 |
| 5 | Dependencies | R18, R28 |
| 6 | Initialize | R12, R26, R6, R1, R5, R25, R23, R15, R19 |
| 7 | Entry | R13, R30, R20 |
| 8 | Execute | R24, R27, R29, R31 |
| X | Atomicity | R3 |

R27 (CET gate) is execution-only: it gates Phase 8 before any donor write.

R21 and R16 are implemented by the Parser module above; every later phase consumes its descriptor. R21 (basic PE header validation) runs before R16 (deep RVA/data-directory bounds check); ApiSet redirection (R10) precedes name/ordinal resolution (R22); the entry kind (R13) is selected before the CRT entry is called (R30).

# Execution: Thread Hijacking
- W^X Stub -- code page RX, state page RW, guard page NOACCESS.
- TEB Last Error -- stub saves and restores the thread LastErrorValue.
- Donor Rewind -- restore the original [RSP] return if stub never began.
- Deferred Reclaim -- track stub allocations; free only after donor leaves.
- Private Stack -- stub pivots to its own stack behind a NOACCESS guard page.
- Full Register Save -- stub saves all GPRs and FP/XSAVE, then restores them.
- Wakeability Rank -- rank donors by reliable wake; prefer prompt queue waits.
- Waiting Thread Hijack -- overwrite [RSP] of a WrQueue-waiting worker thread.
- Multi-Round Selection -- retry donor selection across rounds before failing.
- Stub Contract -- save registers, run payload, restore, jump to original return.
- No Suspend or Resume -- The thread wakes naturally when its awaited event fires.
- No New Thread -- never create a thread whose start address is in private memory.
- No APC -- do not queue a user APC; the routine address persists in the APC queue.
- Clean Failure -- no fallback; fail cleanly when no suitable waiting thread exists.
- Kernel Mitigation Probe -- read process mitigation flags from EPROCESS before hijack.
- CET Caveat -- shadow stack may fault a rewritten return address; verify on target first.
- No VEH Neutralization -- do not unlink Warden VEH; the next INT3 would crash the process.
- CET gate -- if EnableUserShadowStack is active, WTH return overwrite is fatal; fail clean.
- MDL Writes -- all target writes through locked MDL; no WriteProcessMemory or VirtualAllocEx.
- No Remote Handles -- use PsLookupProcessByProcessId only; never OpenProcess or DuplicateHandle.
- Verify Return Slot -- confirm [RSP] holds a return address into a syscall wrapper before overwriting.
- Avoid Main Thread -- never hijack the main or UI thread; use a worker thread with WrQueue wait reason.
- No Context Write -- never call PsSetContextThread; no THREAD_SET_CONTEXT access or ETW-Ti context event.

## Injector: Stealth Techniques

# Stealth Techniques: Manual Mapping
- W^X -- write RW, promote RX, never RWX.
- Section protections from characteristics.
- No CFG bitmap writes for the private range.
- Manual mapping -- no LdrLoadDll, no loader list entry.
- Header wipe in the target mapping (kills MZ/PE anchors).
- Kernel-decided everything; user supplies only PID and bytes.
- No PEB loader entry (accepted -- fake entry is more detectable).
- CFG retarget to a legitimate-module ret gadget (no private pointer).

# Stealth Techniques: Execution

The canonical execution list is in `Execution: Thread Hijacking` above. This table states only the signal each technique avoids.

| Technique | Signal avoided |
|---|---|
| Avoid main/UI thread | user-visible stall |
| Multi-round donor selection | predictable donor |
| CET shadow-stack verification | shadow-stack fault |
| No SuspendThread/ResumeThread | scheduler telemetry |
| TEB LastErrorValue save/restore | thread-state corruption |
| Donor rewind | broken return address |
| Wakeability ranking of donor threads | failed wake attempts |
| Kernel mitigation probe via EPROCESS | user-mode query telemetry |
| Private stack with NOACCESS guard page | stack pivot |
| Full GPR + FP/XSAVE save/restore | register discontinuity |
| Deferred reclaim + scrub | stale stub allocation |
| No user APC | APC queue residue |
| MDL writes | user-mode write telemetry |
| Verify return slot | wrong return target |
| No remote handles | handle table telemetry |
| No PsSetContextThread | ETW-Ti THREAD_SET_CONTEXT |
| No new thread | PsSetCreateThreadNotifyRoutine |
| No VEH neutralization | Warden INT3 trampoline crash |
| Waiting Thread Hijack | thread creation/context events |
| CET gate before donor selection | fatal shadow-stack fault |

# Stealth Techniques: Control Plane
- Per-map unique device suffix.
- No brand strings in binaries.
- Remove-lock drain (no fixed sleeps).
- No Event Log imports -- DbgPrintEx only.
- Seqlock snapshot (detects accidental races).
- Explicit DACL -- SYSTEM + Administrators only.
- XOR-encoded diagnostic labels (no plaintext strings).
- Machine-derived device name and per-machine IOCTLs (no fixed artifact).

# Stealth Techniques: Anti-Analysis
- Versioned offsets, re-derived on new builds.
- Per-build signature discovery for undocumented ntdll routines.

# Stealth Techniques: Additional Mitigations
- Module-stomp a signed driver -- disk-vs-memory .text hash catches it.
- Minimize pool allocations -- generic tags only, no distinctive pattern.
- Kernel-origin Zw calls -- most ETW-Ti events flag only user-mode callers.
- No Beep/Null device hijack -- those device objects are explicitly checked.
- PTE backing spoof -- needs file-backed section or MM edits; PatchGuard risk.
- Import wrapper scanning -- FF 25 stubs to ntoskrnl outside a module are flagged.
- MmUnloadedDrivers forensics -- historical unload records reveal transient loaders.
- Directory traversal -- \Driver and \Device directories walked for unlisted objects.
- No new threads -- thread-creation callbacks are common; WTH avoids thread creation.
- Front-load runtime deps -- avoid LoadLibrary; image-load callbacks block late loads.
- Image-backed mapping -- only real PTE fix; changes architecture, adds disk artifact.
- Spoof DriverStart -- point at a legit module base; driver section stays inconsistent.
- KernelHashBucketList -- ci.dll hash records of loaded drivers; extra telemetry table.
- Dispatch pointers in legitimate memory -- IOCTL handlers must point into known modules.
- PiDDBCacheTable -- AVL table of driver loads; clear loader-driver entry under PiDDBLock.
- VAD unlinking -- memory-manager runtime data, not PatchGuard-checked; careful AVL unlink.
- Hypervisor -- needed to reliably defeat kernel driver scanning; out of scope for a driver.
- Fabricate DriverSection -- KLDR_DATA_TABLE_ENTRY into PsLoadedModuleList; PatchGuard high risk.
- Unbacked driver detection -- driver regions compared to disk-backed sections; manual map fails.
- Driver object exposure -- IoCreateDriver gives no PsLoadedModuleList entry; DriverStart unbacked.
- PoolBigPageTable -- maps large allocations to owning tags; finds allocations with no driver object.


### Injector: Verifications

# Injection Logging:
Process Name: Overwatch.exe
The selected process target connected successfully. (PID: ...)

Dispatcher[15] HEADER_VALIDATE -> ... (...)
Dispatcher[16] PAYLOAD_RANGE -> 0x... (...)

Dispatcher[17] INJECT -> 0x... (...)
Dispatcher[18] RESULT -> 0x... (...)

Driver Status: ... (...)

Parser:

  Status: 0x00000000 (STATUS_SUCCESS)

  PE Offset: 0x00000078 | Image Base: 0x0000000180000000
  Size Of Image: 0x001062000 | Headers Size: 0x00000400

  Sections: 6 | Entry Point: RVA 0x00014020
  Directories: 16 | Alignment: 0x1000 / 0x200

  DLL Characteristics: 0x0160 | File Characteristics: 0x2022

Acceptance is the INJECT stage; rejection is PAYLOAD_IMAGE with Parse Status 0xC000000D.

Dispatcher[15] HEADER_VALIDATE -> 0x00000000 (STATUS_SUCCESS)
Dispatcher[16] PAYLOAD_RANGE -> 0x00000000 (STATUS_SUCCESS)
Dispatcher[17] PAYLOAD_IMAGE -> 0xC000000D (STATUS_INVALID_PARAMETER)
Dispatcher[18] RESULT -> 0xC000000D (STATUS_INVALID_PARAMETER)

Driver Status: 0xC000000D (STATUS_INVALID_PARAMETER)


Validating...

Validating driver's connectivity: Connected/Disconnected
Validating privileges: Administrator/Normal
Validating machine binding: matched
Validating command magic: accepted
Validating options mask: known bits only
Validating payload offset: 128
Validating payload range: inside registered region
Validating seqlock: stable snapshot
Validating region ownership: owner handle
Validating completion sentinel: STATUS_PENDING cleared
Validating completion mode: synchronous IOCTL
Validating target architecture: x64
Validating PE architecture: AMD64
Validating driver status: 0x00000000 (STATUS_SUCCESS)

Validation completed successfully.

Validation failed: privileges insufficient.


Analyzing DLL...

Architecture: x64/x86 (x86 and PE32 rejected)
Format: PE32+
PE Offset: ...
Image Base: ...
Section Alignment / File Alignment: ...
Subsystem: ...
DLL Characteristics: ...
File Characteristics: ...
Entry Point: RVA ...
Sections: ...

Parser Scope: headers, sections, directories, entry point
Deferred to Phase 4+: import/export/TLS/load-config table contents

Load Configuration: Present/Not Present
TLS Directory: Present/Not Present
Security Cookie: Present/Not Present
Activation Context Manifest: Present/Not Present
Debug Directory: present / absent
Resource Directory: present / absent

Base Relocations: ...
Exception Directory: ...
Data Directories: ...
Directory Count: ...

CET: ...
CFG: ...

Relocation Types: DIR64 / HIGHLOW

Image Size:
Headers Size:

Import Modules: xxxx, xxx, xxx, ...
Delay-load imports: xxx Modules
Exports Modules: xxx, xxx, xxx, ...
Forwarded Exports: ...
Imports By Ordinal: ...
Bound Imports: ...

Manual-map Modules: ...
API-set References: ...

DLL Analysis complete.

Analysis result: rejected - x86 images are not supported.

Adapting to DLL...

Relocations: applied
IAT: resolved
Bound imports: invalidated
TLS callbacks: registered
.pdata: inserted
CFG pointer: retargeted
Security cookie: initialized
Headers: wiped

Injector has been fully adapted to DLL.

Injecting...
Injected to the target process successfully. (Phase 2 target -- not produced by the shipped build)

Injection failed: 0xC0000002 (STATUS_NOT_IMPLEMENTED).
