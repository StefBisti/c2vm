#ifndef C2VM_VULN_H
#define C2VM_VULN_H

#include <stddef.h>

/* One entry of a grype report's .matches[]. */
struct vuln
{
    char id[32];       /* CVE-2026-31431 */
    char severity[16]; /* Critical High Medium Low Negligible Unknown */
    char package[160]; /* artifact.name */
    char version[96];  /* artifact.version */
    char eco[16];      /* from artifact.purl: deb, generic, pypi... */
};

/*
 * Reads a grype JSON report and fills *out with a malloc'd array. Returns the
 * number of findings — zero is a legitimate answer, unlike an SBOM with no
 * packages, so an empty report is not an error.
 */
size_t vuln_load(const char *path, struct vuln **out);

/* Severity as an index into the conventional order, so reports never sort
   Critical after Low the way alphabetical would. Unknown sorts last. */
int severity_rank(const char *severity);
const char *severity_name(int rank);

#define SEVERITY_COUNT 6

#endif
