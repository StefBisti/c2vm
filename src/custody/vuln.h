#ifndef C2VM_VULN_H
#define C2VM_VULN_H

#include <stddef.h>

/* One entry of a grype report's .matches[]. */
struct vuln
{
    char id[32];
    char severity[16]; /* Critical High Medium Low Negligible Unknown */
    char package[160]; /* artifact.name */
    char version[96];  /* artifact.version */
    char eco[16];      /* from artifact.purl: deb, generic, pypi... */
};

// read report and fill *out. returns the number of findings
size_t vuln_load(const char *path, struct vuln **out);

// index and name of severity
int severity_rank(const char *severity);
const char *severity_name(int rank);

#define SEVERITY_COUNT 6

#endif
