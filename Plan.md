### Injector: DLL Requirements:

1. TLS callbacks -- run TLS callbacks before the DLL entry point.
2. x64-only enforcement -- refuse PE32/x86 images and WOW64 targets.
3. Undocumented routine resolution -- locate required ntdll loader symbols.
4. Base relocations -- apply DIR64 / HIGHLOW fixups from the ImageBase delta.
5. PE validation -- validate PE32+ headers and refuse architecture mismatches.
6. Forwarded exports -- follow forwarded exports recursively with a depth cap.
7. Static TLS -- allocate TLS index from PEB bitmap and init TEB slots in kernel.
8. Section mapping -- handle SectionAlignment vs FileAlignment and zero-fill .bss.
9. API-set redirection -- resolve api-ms-win and ext-ms-win names via ApiSetSchema.
10. .pdata registration -- register .pdata in the inverted function table from kernel.
11. Configurable entry point -- support DllMain, a named export, or an ordinal as entry.
12. Load-config validation -- validate GuardFlags and data-directory indices before use.
13. Delay-load imports -- resolve delay-load descriptors including ordinal and name thunks.
14. Mitigation detection -- query process mitigations at runtime and adapt CFG / CET / ACG.
15. CET / shadow stack -- honor CETCOMPAT and GuardEHContinuations, fail closed on conflict.
16. Section protection mapping -- map all five protection cases from section characteristics.
17. Dependency loading -- prefer already-loaded modules; manually map missing ones in kernel.
18. Image allocation -- reserve SizeOfImage in the target process and return the mapped base.
19. Deep PE validator -- bounds-check every RVA, size and data directory against SizeOfImage.
20. Imports by name/ordinal -- resolve both name and ordinal imports, including ordinal-only APIs.
21. Security cookie -- init and preserve the /GS security cookie and its complement from load config.
22. Section protections -- set correct per-section memory protections (RX .text, RW .data, RO .rdata).
23. Dependency refcount + cycle tracking -- track dependency records with refcounts and handle cycles.
24. Control Flow Guard -- set GFIDS bits in the CFG bitmap and patch check/dispatch pointers from kernel.
25. CRT entry point -- call _DllMainCRTStartup / _CRT_INIT with DLL_PROCESS_ATTACH, not DllMain directly.
