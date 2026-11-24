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

Implemented in `Driver/Utilities/Parser/Format.h` and `Format.c`. Phase 0 (R21, R16) is complete and wired into `Dispatcher.c`. Phases 1 through 7 are implemented in `Reserve/`, `Mapping/`, `Relocate/`, `Imports/`, `Dependencies/` and `Initialize/` (which hosts both Phase 6 Initialize and Phase 7 Entry); `InjectorExecute` orchestrates them but returns `STATUS_NOT_IMPLEMENTED` while phase 8 (Execute) is deferred.

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

The report now includes import and export names with counts, a delay-module count (delay names are not stored), forwarded and ordinal counts, ApiSet references, TLS callback count, security cookie RVA, guard flags, relocation type counts, directory presence flags and manifest detection. Import table contents are resolved in Phase 4; the remaining table contents are measured by later phases.

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

Report extension: add allocation fields to the existing `AMGER_PARSER_REPORT` in the 4096-byte area (current size is measured by the report harness; ample room remains). Client renders a second `Allocation:` block with white labels, white separators and green/red values, exactly like the parser block:

```
Allocation:

  Status: 0x00000000 (STATUS_SUCCESS)
  Target PID: 9956
  Image Size: 0x001062000

  Remote Base: 0x0000020000000000
  Protection: READWRITE (reserve only)

  Execution: deferred (phase 8)
```

Verification order: test on `notepad` first with the client console. Until Phase 8 (Execute) lands, INJECT must still return `STATUS_NOT_IMPLEMENTED` — a successful allocation must not claim injection succeeded. Overwatch is tested only after the entire injector is finished.

## Mapping

R8 and R11 are implemented in `Driver/Execution/Mapping/Sections.h` and `Sections.c`; `Create.bat` compiles and links `Sections.obj`. `Injector.c` keeps the Phase 1 reservation alive and calls this module before any later phase. Protection is a separate `SectionsSeal` pass at the end of the currently implemented chain so relocations, imports and initialization can still write.

API:
- `MapSectionsMap(CONST AMGER_PE_IMAGE* Image, HANDLE ProcessId, uint64_t RemoteBase, PAMGER_MAP_REPORT Out)` — commits and copies.
- `SectionsSeal(CONST AMGER_PE_IMAGE* Image, HANDLE ProcessId, uint64_t RemoteBase, PAMGER_MAP_REPORT Out)` — merges characteristics per page and promotes once.
- `MapSectionsRevert(HANDLE ProcessId, uint64_t RemoteBase)` — paired R3 rollback.

Sequence:
1. Keep the Phase 1 reservation; do not release it on the success path.
2. Commit `SizeOfImage` as `PAGE_READWRITE` at the reserved base with one kernel-origin `ZwAllocateVirtualMemory(MEM_COMMIT)` while attached. Never commit executable protection.
3. Copy `SizeOfHeaders` bytes from image offset 0 to RVA 0.
4. For each section: destination `RemoteBase + VirtualAddress`; source `Image->Base + RawOffset`; copy `min(VirtualSize, RawSize)`; zero-fill `VirtualSize - RawSize` when `VirtualSize > RawSize` (`.bss`). FileAlignment vs SectionAlignment is handled by RVA placement — a flat file copy is wrong.
5. `SectionsSeal` groups section ranges by **page**, ORs the characteristics of overlapping regions, merges contiguous pages with equal protection, and applies one `ZwProtectVirtualMemory` call per run. Never leave a page RWX; promote RW → RX exactly once. Pages with no section or header coverage become `PAGE_NOACCESS`.
6. Five protection cases from characteristics: no access -> `PAGE_NOACCESS`; execute only -> `PAGE_EXECUTE`; execute + read -> `PAGE_EXECUTE_READ`; read only -> `PAGE_READONLY`; read + write -> `PAGE_READWRITE`. Execute+write is promoted to `PAGE_EXECUTE_READ` because writes are already complete.
7. Header wipe (`R20`) stays in Phase 7, not here. The last `ZwProtectVirtualMemory` length is clamped to `SizeOfImage` when the image is not page-aligned.

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

  Commit: read/write
  Protections: applied (no RWX)
  Page Groups: 7

  Rollback: mapping reverted
  Execution: deferred to Phase 6
```

Verification order: test on `notepad` first. INJECT must still return `STATUS_NOT_IMPLEMENTED`; the `Mapping:` block is the proof. Confirm with WinDbg `!vad` that the region is private and non-executable before promotion, then executable after. Overwatch is tested only after the entire injector is finished.

## Relocation

R7 is implemented in `Driver/Execution/Relocate/Fixups.h` and `Fixups.c`; `Create.bat` compiles and links `Fixups.obj`. Folder and file names are one word each and differ (`Relocate` / `Fixups`), matching `Reserve`, `Mapping` and `Parser`.

API:
- `FixupsApply(CONST AMGER_PE_IMAGE* Image, HANDLE ProcessId, uint64_t RemoteBase, uint64_t Delta, PAMGER_RELOC_REPORT Out)` — applies base relocations in place through one locked MDL.

Sequence:
1. Delta = `RemoteBase - Image->ImageBase`, computed with unsigned 64-bit wrap; the manager-chosen base is normally below the preferred `0x180000000`.
2. Data directory index 5 must exist and fit inside `SizeOfImage`; a missing or empty `.reloc` fails clean, per R7.
3. One MDL covers the whole image, because fixup targets live in code and data sections, not inside `.reloc`. It is locked `UserMode / IoWriteAccess` while attached to the target.
4. Walk blocks (`PageRVA`, `BlockSize`), bounds-check the block and every entry before writing, and apply `DIR64 (10)` and `HIGHLOW (3)`. `ABSOLUTE (0)` is skipped; unknown types fail clean. All fields are read and written byte-wise.
5. Every write happens while the image is still `RW`. `SectionsSeal` runs afterwards, so no page toggles back to writable and no RWX state is created.
6. Any failure returns a named NTSTATUS; the injector releases the whole reservation, so no partially relocated image survives.

Detection-aware decisions:
- No `LoadLibrary`, no loader lock, no CFG bitmap update and no new ETW-TI protection event: the only writes are through an MDL into an already committed private region.
- No user-mode API chain, no remote handle, no `WriteProcessMemory`; the target is referenced with `PsLookupProcessByProcessId` only.
- No string literal, no pool tag and no file-backed section: the descriptor and both reports stay on the stack.

Report extension: `AMGER_RELOC_REPORT` (Status, FailureStage, RelocRva, RelocSize, Blocks, Fixups, DIR64, HIGHLOW, Skipped, Flags, Delta, RemoteBase) joined `Allocation` and `Mapping` in the 4096-byte report area. The exact `sizeof(AMGER_PARSER_REPORT)` is measured by the report harness; the static assert in `Protocol.h` enforces the 4096-byte bound. The client renders a `Relocations:` block in the same white-label / green-red style. Mapping and Relocation also print `Failure Stage:` when Status is non-zero, so the exact failing kernel pass is visible.

Verified offline against `Assets\Target.dll`: 21 blocks, 1609 `DIR64` fixups, 11 `ABSOLUTE` skips, zero `HIGHLOW`, matching the parser's `RelocDir64Count`; the seal algorithm yields 7 page groups. Driver builds `/W4 /kernel` clean; `Verify.bat` passes.

Verification order: test on `notepad` first. INJECT must still return `STATUS_NOT_IMPLEMENTED`; the `Relocations:` block is the proof. Overwatch is tested only after the entire injector is finished.

## Imports

R10, R22, R4, R14 and R9 are implemented in `Driver/Execution/Imports/Lookup.h/.c` and `Driver/Execution/Imports/Binding/Resolve.h/.c`; `Create.bat` compiles and links `Lookup.obj` and `Resolve.obj`. Folder and file names are one word each and differ from the folder (`Imports` / `Lookup`, `Binding` / `Resolve`).

API:
- `LookupInitialize(Out)` — reads PEB and obtains `Ldr` and `ApiSetMap`. Called once while attached.
- `LookupResolveApiSet(...)` — resolves `api-ms-win` / `ext-ms-win` names through schema v6, v4 or v2.
- `LookupFindModule(...)` — case-insensitive Unicode lookup in a private table (for Phase 5) and in `InLoadOrderModuleList`.
- `LookupGetExport(...)` — name/ordinal export lookup with forwarder strings returned for the caller to follow.
- `ResolveImports(Image, ProcessId, RemoteBase, Out)` — drives descriptors, IAT writes, delay descriptors and bound-import invalidation.

Sequence:
1. Attach to the target, read PEB via `ZwQueryInformationProcess(ProcessBasicInformation)`. x64 offsets: `PEB+0x18` = Ldr, `PEB+0x68` = ApiSetMap, `PEB_LDR_DATA+0x10` = load-order head, `LDR_DATA_TABLE_ENTRY+0x30` = DllBase, `+0x40` = SizeOfImage, `+0x58` = BaseDllName. Every user read is bounded to the x64 user range and guarded by SEH; list traversal is capped at 512 entries.
2. ApiSet before name lookup. v6: lowercase name up to the last `-`, `hash = hash * HashMultiplier + lower(wchar)`, binary-search the hash table, validate every namespace offset against the header `Size`, then read the host DLL from `ValueOffset/ValueLength`. Lowercasing is ASCII-only (`A`–`Z`), which covers every `api-`/`ext-` contract name. v4 uses binary search on plain Unicode names; v2 uses the documented sorted `DLLHOSTDESCRIPTOR` table (`NameOffset +0`, `StringLength +4`, `OffsetDllRedirector +8`) with the two-slot `REDIRECTION` layout (host in the second slot).
3. Module resolution: Unicode case-insensitive compare against `BaseDllName`, private table first, loader list second. Phase 5 can register manually mapped modules through `LookupRegisterPrivate` without rewriting this phase.
4. Export resolution: parse directory 0 inside the module's `SizeOfImage`; names are matched case-sensitively, ordinals validated against `NumberOfFunctions`. A function RVA inside the export directory is a forwarder string (`MODULE.Symbol` or `MODULE.#ordinal`); follow it with a depth cap of 8.
5. IAT: walk `OriginalFirstThunk` (fall back to `FirstThunk`); 8-byte entries, high bit = ordinal, otherwise 31-bit Hint/Name RVA. Write resolved addresses to `FirstThunk` through one MDL-locked system mapping. Cap 8192 thunks per descriptor.
6. Delay imports: handle both RvaBased descriptors and legacy VA fields (subtract the preferred base). Resolve `ImportNameTable` and write `ImportAddressTable` plus the module-handle slot.
7. Bound imports: zero data directory 11 in the mapped headers so stale binding data cannot be used.
8. Missing modules are counted as deferred for Phase 5, never a hard failure. Name/ordinal exports missing from a present module are counted as unresolved.

Detection posture against Eidolon/Warden (`.analysis`):
- PEB, loader list, loaded modules and ApiSet schema are **read only**. No module is linked into the loader list, no PEB field is written, no loaded module is patched.
- No VEH unlink, no INT3 trampoline change, no timing-hook neutralization: `FkCheck`, `VCheck`, `IntegrityCk`, Warden's first-chance VEH and the 24k runtime INT3 bytes in `Overwatch_Loader.dll` are untouched.
- No user-mode API calls and no remote handles. Warden's user-mode hooks on `NtOpenProcess`, `NtReadVirtualMemory`, `NtQuerySystemInformation`, `NtCreateThreadEx` and `NtProtectVirtualMemory` are bypassed by kernel-origin `Zw` calls and passive reads.
- IAT writes target only the private, already-committed image while it is RW; no protection change occurs here, so no new ETW-TI PROTECTVM event is generated before the single seal pass.
- No brand strings, no API-set name literals emitted by the driver; ApiSet names come from the payload and the namespace schema.

Report extension: `AMGER_IMPORT_REPORT` (Status, FailureStage, Modules, DelayedModules, FunctionsResolved, ByName, ByOrdinal, Forwarded, ApiSetRedirects, Unresolved, Deferred, LookupErrors, DeferredOrdinal, DeferredModule, DeferredSymbol, DeferredModuleCount, DeferredModules, Flags, RemoteBase) joined the other phase reports; the static assert in `Protocol.h` keeps `sizeof(AMGER_PARSER_REPORT)` within the 4096-byte area (the report harness prints the exact value). `LookupErrors` keeps malformed-table failures visible instead of folding them into ordinary unresolved counts. Failure stages name PEB, ApiSet, MDL, descriptor, module, export, forward, IAT, delay and bound passes. The client renders an `Imports:` block in the same white-label / green-red style, including a `Pending:` line that names the exact module Phase 5 must provide when any import is deferred.

Verified offline against `Assets\Target.dll`: 8 import modules, 170 imports by name, 1 by ordinal, 0 delay descriptors — matching the parser summary. Driver builds `/W4 /kernel` clean; `Verify.bat` passes.

Verification order: test on `notepad` first. The `Imports:` block is the proof; a missing graphics DLL is reported as deferred, not as a failure. INJECT must still return `STATUS_NOT_IMPLEMENTED`. Overwatch is tested only after the entire injector is finished.

## Dependencies

R18 and R28 are implemented in `Driver/Execution/Dependencies/Images.h/.c` and `Dependencies/Table/Graph.h/.c`; `Create.bat` compiles and links `Images.obj` and `Graph.obj`. Folder and file names are one word each and differ from the folder (`Dependencies` / `Images`, `Table` / `Graph`).

API:
- `ImagesMapDependency(...)` — kernel-only file acquisition, PE validation, reservation, section mapping and relocation of one dependency.
- `DependenciesResolve(...)` — bounded rounds, dependency table with refcount/state/depth, cycle skipping, rebind after each mapping round.

Sequence:
1. Collect deferred module names from `AMGER_IMPORT_REPORT.DeferredModules` (added for this phase; the client's single `Pending:` name remains for readability).
2. Open `\SystemRoot\System32\<name>` with `ZwCreateFile` using `FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`, shared read/write/delete, `FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT` and `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE`. No write access and no user handle.
3. Query `FileStandardInformation`, enforce a 256 MiB cap, read the whole file into a transient `PagedPool` buffer with a neutral zero tag, then close the handle.
4. Validate with `PeParseAndValidate`, reserve `SizeOfImage`, map with `MapSectionsMap`, relocate with `FixupsApply`, then free the raw buffer and register the base through `LookupRegisterPrivate`.
5. Re-run `ResolveImports` on the primary image and on each mapped dependency; feed any new deferred names into the next round. Maximum 4 rounds, 16 modules, 64 pending names.
6. Repeated dependency names increment a refcount; a module already in `loading` state is a cycle and is counted, never recursed into.
7. Loader-list entry counts are measured before and after the phase with `LookupCountLoaderModules`, and the primary import report is captured before/after so `DeferredBefore/After`, `ReboundFunctions` and `DependencyImportsResolved` are real values rather than design claims.
8. Any hard failure releases every dependency mapping plus the primary reservation. On the current R3 rollback path, the published `Bases` array lets the injector release dependency mappings together with the primary image, so no private dependency VAD survives either.

Detection posture against Eidolon/Warden (`.analysis`):
- Kernel handles bypass `ObRegisterCallbacks`; no user-mode API, no `LoadLibrary`, no remote handle.
- No `NtCreateSection`/`NtMapViewOfSection` image section is created, so no `PsSetLoadImageNotifyRoutine` callback fires. Microsoft documents that SEC_IMAGE_NO_EXECUTE sections also suppress these callbacks; this design avoids section objects entirely.
- PEB/LDR remains read-only; no module is linked into the loader list and no loaded module is patched.
- No VEH, INT3 trampoline, timing hook or Warden integrity table is touched.
- Known residual signals: kernel file create/read telemetry, a transient neutral-tagged pool buffer, private executable VADs and PROTECTVM events. These are invisible to the target's user-mode AC but would be visible to a kernel EDR; absolute undetection is not claimed.

Report extension: `AMGER_DEP_REPORT` (Status, FailureStage, ModulesMapped, ModulesLoaded, BytesRead, Rounds, Cycles, Failures, Flags, PrimaryBase, BaseCount, MappedNameCount, Bases, MappedNames, FileOpens, ModulesRegistered, DeferredBefore, DeferredAfter, ReboundFunctions, DependencyImportsResolved, LoaderEntriesBefore, LoaderEntriesAfter) joined the other phase reports; the mapped bases are published so the injector can release every dependency on rollback. The client renders a `Dependencies:` block with measured evidence only — file opens, bytes read, manually mapped and registered counts, rounds/failures/cycles, deferred-before/after, rebound primary functions, dependency imports resolved, loader-entry counts before/after, and a mapped module name/base list. No hardcoded design claims remain in that block; failure stages cover file, parse, allocate, map, relocate, register, import and round limits.

Verification order: test on `notepad` first. Expect `Imports:` to reach `Functions Resolved: 171` with no `Pending:` line, and `Dependencies:` to show the graphics DLLs mapped from System32. INJECT must still return `STATUS_NOT_IMPLEMENTED`. Overwatch is tested only after the entire injector is finished.

## Initialize

Phase 6 (R12, R26, R6, R1, R5, R25, R23, R15, R19) is implemented in `Driver/Execution/Initialize/Runtime.h/.c`; `Create.bat` compiles and links `Runtime.obj`. It prepares only state a manually mapped module needs before its entry point runs, and publishes a measured `AMGER_INIT_REPORT` in the shared report area.

API:
- `InitializePhase(const AMGER_INIT_CONTEXT* Context)` — validates load config and GuardFlags, seeds the security cookie and its complement, allocates a TLS index from the PEB `RTL_BITMAP` at `PEB+0x78` (with `TlsExpansionBitmap` at `PEB+0x238` and real index `64 + bitPos` when the primary bitmap is full), installs per-thread TLS template blocks and TEB slots, resolves `RtlAddFunctionTable`/`RtlPcToFileHeader`, retargets the CFG guard-check pointer, detours `ntdll!RtlPcToFileHeader`, registers `.pdata`, and runs process-attach TLS callbacks plus `RtlAddFunctionTable` through a kernel-queued user APC whose stub lives in a private RX page.
- `InitializeRevert(const AMGER_INIT_CONTEXT* Context)` — unregisters the R25 notify callback, restores the ntdll detour, clears the TLS bitmap bit, restores per-thread TEB slots, frees private TLS pages and the template, and releases the APC pages when no APC can still run.

All COW-sensitive writes use one `ZwProtectVirtualMemory(PAGE_READWRITE)` -> `MmCopyVirtualMemory` -> protection-restore path. No RWX mapping is ever created, and no MDL alias bypasses copy-on-write. Each R25 per-thread stub gets its own code/data page pair; the code page is promoted RW -> RX once before the APC is queued, so a page is never both writable and executable.

R6 (activation context) is implemented as measured non-applicability. `DetectActivation` walks the resource tree for `RT_MANIFEST` (id 24) and reports the manifest ID, byte count and a content hash. No activation context is created: the loader's ID-1/ID-2 actctx is produced only inside `LoadLibrary` and stored in a loader data entry, a manually mapped image has neither, there is no documented in-memory-XML actctx API, and Phase 4 resolves imports directly without SxS binding. Activation is thread-local, so an APC-time activation would not apply to the entry-point thread. No target state is changed by R6.

R25 (thread TLS callbacks) is implemented with a deliberately tiny `PsSetCreateThreadNotifyRoutine` callback that only enqueues an event into a bounded ring and arms a passive-level work item. All user-memory access, TLS-slot installation and user-APC queuing happen in that work item, removing the deep chain and large stack frames that caused the earlier `0x7f` bugcheck. `DLL_THREAD_ATTACH` is delivered on the new thread after loader thread-init; delete events are counted only, never reported as callbacks fired, because an exiting thread never returns to user mode and no user APC can deliver `DLL_THREAD_DETACH` to it. Each attach uses a private RW job page and a separate code page promoted to RX before the APC is queued. The notify registration and all per-thread pages are released by `InitializeRevert`; with phase 8 deferred the payload is rolled back in the same inject, so the report measures registration and event counts but normally sees zero create events.

Report fields (`AMGER_INIT_REPORT`) are all read back from the target or taken from calls that returned a status: load-config RVA/size/struct size/GuardFlags, cookie RVA and low half, activation-context status plus manifest state/id/bytes/hash, TLS callback count, index and bitmap size/buffer/bits, raw byte count, patched-thread count, notify status and create/delete/dropped/attach/detach counters, routine counts, APC runs/failures/started/completion/boosters, detour address and byte count, `.pdata` table/entry counts, CFG pointer before/after, selected ret gadget, CFG readback/absent flags, and failure stage. `BuildId` is retained in the report for stale-driver diagnosis but is not displayed by the client.

R24/R27/R29 are implemented as **measurement only** while phase 8 stays deferred. A read-only native `ProcessMitigationPolicy` query publishes the CFG, user-shadow-stack and dynamic-code policy words plus its query status and returned length; it opens the target with `PROCESS_QUERY_LIMITED_INFORMATION`, the access the native class actually requires, so protected targets are not rejected by an unnecessary `PROCESS_QUERY_INFORMATION` request. The exact union size of `PROCESS_MITIGATION_POLICY_INFORMATION` is not published in the WDK headers, so the query uses a zeroed 64-byte buffer with `POLICY` at offset 0 and reads the flags at offset 4, falling back to an exact 8-byte buffer if the kernel requires a precise length. The returned length is published so a mismatch is visible instead of being mistaken for a benign all-zero policy. The reported `CetRiskClass` and CET-scoped `ExecutionAllowed` gate are computed from those words so a future return-address hijack cannot ignore them; a failed or unavailable query closes the gate. The gate is deliberately CET-only and does not claim CFG or dynamic-code policy is absent — those are published separately. The native information class is declared in the WDK KM headers but Microsoft does not document it as a supported driver API, the bit layouts come from the shipped SDK, and no EPROCESS offset is hardcoded. A zero `GuardCFCheckFunctionPointer` is reported as `Pointer = Absent` and the retarget pass exits without writing, because `0 - ImageBase` underflows and would otherwise produce a bogus pointer. `Pointer = Present` means both the load-config field and the relocated global were read back after patching. The TLS callback budget stays at 16 to keep the APC stack frames below the size that previously caused a `0x7f` bugcheck; an over-budget callback array fails explicitly rather than being silently truncated. The gate does not yet factor in the parser's CETCOMPAT bit (R29 behavior) or register dynamic EH-continuation targets; those require user-mode CET APIs that this design deliberately avoids, so full CET correctness for manually mapped code remains an explicit limitation.

Verification order: test on `notepad` first. The `Initialization:` block is the proof; INJECT must still return `STATUS_NOT_IMPLEMENTED` because phase 8 (Execute) is deferred. Overwatch is tested only after the entire injector is finished.

## Entry

Phase 7 (R13, R30, R20) is implemented in `Driver/Execution/Initialize/Runtime.c` as `InvokeEntryPhase`, reusing the phase-6 user-APC machinery. Static asserts in `Protocol.h` keep the wire layout fixed across the client and driver.

Selection (R13) arrives in `AMGER_COMMAND_HEADER.Reserved[16..63]` as an `AMGER_ENTRY_CONTROL` and is copied under the seqlock into the kernel-local snapshot. Three kinds are supported: the image's `AddressOfEntryPoint` (the CRT startup for an MSVC DLL), a named export, and an ordinal-only export. Export lookup reuses `LookupGetExport` on the mapped base and rejects forwarders; resolution happens **before** any header write because the export directory is located through the PE optional header.

R30 calls the resolved entry **once** through a dedicated user APC whose stub lives in a private RX page and whose single job block lives in a separate RW page. The call uses the documented x64 three-argument form (`rcx = RemoteBase`, `rdx = 1 /* DLL_PROCESS_ATTACH */`, `r8 = NULL`) with 32 bytes of shadow space and 16-byte stack alignment; the 64-bit RAX result is read back after the completion marker and only its low 32 bits are published as `EntryResult` (the defined width for a `BOOL` return). A zero return is a **measured payload result**, not an engine failure: many manual-map payloads have `DllMain` refuse process attach so a normal `LoadLibrary` fails, with the real work in an exported entry such as `ManualEntry`. The driver records `AMGER_ENTRY_FLAG_CRT_FALSE` and continues to header erase and seal; it never calls the CRT a second time because the first call already ran its own detach unwind. The `.pdata` table is registered by Phase 6 before this call so CRT code that uses SEH can unwind.

R20 erases `SizeOfHeaders` bytes at the mapped base **after** the CRT entry returns and **before** `SectionsSeal` promotes the header pages to `PAGE_READONLY`. This ordering is required: MSVC CRT attach reads the PE headers at `__ImageBase` (`__scrt_is_nonwritable_in_current_image`) to decide dynamic TLS initialization and static-vs-dynamic CRT handling; wiping earlier silently disables both. The erase is verified by reading back the MZ and PE signature offsets and requiring both to be zero, and only measured values are published in `AMGER_ENTRY_REPORT` (status, stage, kind, RVA/address, result, APC counters, bytes wiped and zero-verification).

All Phase 6/7 user APCs share two global counters (not the per-invocation state, which is zeroed on each call). `g_apcOutstanding` tracks KAPC lifetime and is decremented by the kernel/rundown routine at APC_LEVEL — **before** the user stub runs, so it is not a completion signal. `g_apcStubPending` is the authoritative "a stub may still execute" signal: incremented on queue and decremented only when the poll loop observes `completion == 1`. On a timeout it stays positive, so `InitializeApcOutstanding()` remains TRUE and `InjectorExecute` skips the VAD release — a late stub calls into the mapped image, so unmapping first would crash the target. A late APC delivered after the next invocation starts cannot corrupt either counter because both are global. Entry resolution also requires the RVA to lie inside an executable section and rejects header-resident entry points, both of which would otherwise fault and leave a queued APC. The `CALLED` flag is set from the completion marker regardless of the CRT return value, and a zero return is published as measured (`AMGER_ENTRY_FLAG_CRT_FALSE`) rather than treated as an engine failure.

The APC entry call runs outside the loader lock on an arbitrary target thread; payload `DllMain` restrictions still apply and the interrupted thread may hold application or loader locks. A headerless image cannot resolve its own exports via `GetProcAddress(self)`, and CRT per-thread state established on the APC thread is not automatically present on the Phase 8 donor — those are payload/Phase 8 concerns, not engine measurements. No absolute undetection is claimed: private executable VADs and kernel-caller ETW remain.

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
- XOR-encoded status/log diagnostic labels in the client image (the client still renders plaintext UI strings and the driver keeps a few DbgPrintEx diagnostic formats).
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
Deferred to Phase 6+: export/TLS/load-config table contents

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
