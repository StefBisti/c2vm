#ifndef C2VM_SBOM_H
#define C2VM_SBOM_H

#include <stddef.h>

// One entry of an SPDX document's .packages[]
struct pkg
{
    char name[160];
    char version[96];
    char eco[16];
};

// Reads an SPDX JSON document and fills *out with a malloc'd array, then returns the number of packages
size_t sbom_load(const char *path, struct pkg **out);

/* "deb" -> how many entries carry it. Returns 0 if the ecosystem is absent. */
size_t sbom_count_eco(const struct pkg *p, size_t n, const char *eco);

#endif
