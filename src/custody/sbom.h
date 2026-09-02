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
/* Finds the first "pkg:<type>/ in a JSON fragment and writes <type> to out,
   or "none" if there is no purl. Shared with vuln.c, which reads the same
   purls out of grype's artifact objects. */
void purl_ecosystem(const char *elem, char *out, size_t cap);

size_t sbom_count_eco(const struct pkg *p, size_t n, const char *eco);

#endif
