#ifndef AMGER_IMAGES_H
#define AMGER_IMAGES_H

/*
 * Images.h - kernel-only dependency image acquisition and mapping.
 *
 * Opens the DLL with a kernel handle, reads the raw bytes into a transient
 * buffer, validates them with the Phase 0 parser, then maps and relocates the
 * image with the same primitives used by the primary payload. No user-mode
 * API, no section object, no loader-list entry and no image-load callback.
 */

#include "Graph.h"

#define AMGER_POOL_TAG_RAW 0x22222222u  /* four quotes: neutral, printable */

NTSTATUS ImagesMapDependency(AMGER_DEP_GRAPH* graph, AMGER_DEP_ENTRY* entry);

#endif /* AMGER_IMAGES_H */
