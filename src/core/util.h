#ifndef C2VM_UTIL_H
#define C2VM_UTIL_H

#include <stddef.h>

/*
 * Sorts an array and removes adjacent duplicates in place, returning the
 * number of elements kept. Both SBOM packages and grype findings arrive with
 * duplicates - one entry per cataloger or matcher that produced it - and left
 * in they inflate every count downstream.
 */
size_t dedupe_sorted(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));

/*
 * Locates an external tool. Commands run under sudo, and root's PATH does
 * not include the ~/.local/bin the anchore and sigstore installers write to,
 * so $SUDO_USER's home is searched too. Writes into caller-provided storage:
 * the result outlives many P() calls and must not live in that pool.
 */
const char *tool_path(const char *tool, const char *override, char *found, size_t cap);

#endif
