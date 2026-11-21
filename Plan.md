### Injector Requirements:

1. Static TLS -- register via LdrpHandleTlsData and init TEB slots.
2. x64-only enforcement -- refuse PE32/x86 images and WOW64 targets.
3. Base relocations -- apply DIR64 / HIGHLOW fixups from the ImageBase delta.
4. Worker SEH -- wrap mapping loops in __try/__except to contain bad-DLL AVs.
5. Forwarded exports -- follow forwarded exports recursively with a depth cap.
6. PE validation -- validate PE32+ headers and refuse architecture mismatches.
7. W^X transitions -- map RW, promote to RX per section, never leave RWX pages.
8. Injection mutex -- serialize concurrent injections with a per-injection KEVENT.
9. Section mapping -- handle SectionAlignment vs FileAlignment and zero-fill .bss.
10. API-set redirection -- resolve api-ms-win and ext-ms-win names via ApiSetSchema.
11. TLS detach -- run DLL_PROCESS_DETACH callbacks and free the TLS index on unload.
12. TLS callbacks -- call TLS callbacks with DLL_PROCESS_ATTACH before the entry point.
13. Load-config validation -- validate GuardFlags and data-directory indices before use.
14. Configurable entry point -- support DllMain, a named export, or an ordinal as entry.
15. Signature discovery -- version-scan undocumented routines with re-derivable patterns.
16. Eject reversal -- undo every registration on eject: TLS, function table, CFG, region.
17. Dependency loading -- resolve already-loaded modules first, load missing ones via APC.
18. Mitigation detection -- query process mitigations at runtime and adapt CFG / CET / ACG.
19. Delay-load imports -- resolve delay-load descriptors including ordinal and name thunks.
20. Section protections -- set per-section RX / RW / RO protections before promoting to RX.
21. Control Flow Guard -- register GFIDS call targets and patch CFG check/dispatch pointers.
22. CET / shadow stack -- honor CETCOMPAT and GuardEHContinuations, fail closed on conflict.
23. Deep PE validator -- bounds-check every RVA, size and data directory against SizeOfImage.
24. PASSIVE_LEVEL + MDL -- stay PASSIVE_LEVEL, keep user pages MDL-locked, detach on every exit.
25. User-mode execution -- APC/worker path in the target for ntdll/KernelBase calls from ring 0.
26. Imports by name/ordinal -- resolve both name and ordinal imports, including ordinal-only APIs.
27. .pdata registration -- register the exception directory via a kernel-compatible path before TLS.
28. Security cookie -- init and preserve the /GS security cookie and its complement from load config.
29. Header stomp -- erase PE headers and scrub section names after mapping, as a configurable policy.
30. CRT entry point -- call _DllMainCRTStartup / _CRT_INIT with DLL_PROCESS_ATTACH, not DllMain directly.
