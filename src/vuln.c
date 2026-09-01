#include "vuln.h"
#include "json.h"
#include "run.h"
#include "sbom.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

/*
 * The same walk sbom.c does, over grype's .matches[] instead of SPDX's
 * .packages[]. Kept as a separate file rather than generalised: the two
 * documents agree on nothing but their bracket structure.
 */

static const char *SEVERITIES[SEVERITY_COUNT] = {
    "Critical", "High", "Medium", "Low", "Negligible", "Unknown"};

int severity_rank(const char *severity)
{
    for (size_t i = 0; i < NELEMS(SEVERITIES); i++)
        if (!strcmp(severity, SEVERITIES[i]))
            return (int)i;
    return SEVERITY_COUNT - 1; /* anything unrecognised is Unknown */
}

const char *severity_name(int rank)
{
    if (rank < 0 || rank >= SEVERITY_COUNT)
        return "Unknown";
    return SEVERITIES[rank];
}

static size_t dedupe(struct vuln *v, size_t n);

static char *slurp(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        die("cannot stat %s: %s", path, strerror(errno));

    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot read %s: %s", path, strerror(errno));

    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf)
        die("out of memory reading %s (%lld bytes)", path,
            (long long)st.st_size);

    size_t got = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);

    buf[got] = '\0';
    return buf;
}

/* A CVE description containing a brace must not move the depth counter. */
static const char *skip_string(const char *p)
{
    p++;
    while (*p)
    {
        if (*p == '\\' && p[1])
            p += 2;
        else if (*p == '"')
            return p + 1;
        else
            p++;
    }
    return p;
}

size_t vuln_load(const char *path, struct vuln **out)
{
    char *doc = slurp(path);

    char *key = strstr(doc, "\"matches\"");
    if (!key)
        die("%s has no \"matches\" array; is it a grype JSON report?", path);

    char *p = strchr(key + strlen("\"matches\""), '[');
    if (!p)
        die("%s: \"matches\" is not an array", path);
    p++;

    size_t cap = 256, n = 0;
    struct vuln *vs = malloc(cap * sizeof *vs);
    if (!vs)
        die("out of memory");

    int depth = 0;
    char *start = NULL;
    bool closed = false;

    for (; *p; p++)
    {
        if (*p == '"')
        {
            p = (char *)skip_string(p) - 1;
            continue;
        }

        if (*p == '{')
        {
            if (depth == 0)
                start = p;
            depth++;
            continue;
        }

        if (*p == '}')
        {
            depth--;
            if (depth > 0 || !start)
                continue;

            char save = p[1];
            p[1] = '\0';

            /*
             * Anchored on the section, not searched from the element start:
             * "id" also appears inside artifact, and "name" and "version"
             * appear inside matchDetails. Both objects are found by their
             * own key first, which is what keeps each lookup in the right
             * part of the record.
             */
            char *id = json_get_in(start, "vulnerability", "id");
            char *sev = json_get_in(start, "vulnerability", "severity");
            char *pkg = json_get_in(start, "artifact", "name");
            char *ver = json_get_in(start, "artifact", "version");

            if (id && sev && pkg)
            {
                if (n == cap)
                {
                    cap *= 2;
                    struct vuln *grown = realloc(vs, cap * sizeof *vs);
                    if (!grown)
                        die("out of memory");
                    vs = grown;
                }

                struct vuln *e = &vs[n++];
                snprintf(e->id, sizeof e->id, "%s", id);
                snprintf(e->severity, sizeof e->severity, "%s", sev);
                snprintf(e->package, sizeof e->package, "%s", pkg);
                snprintf(e->version, sizeof e->version, "%s", ver ? ver : "");

                /* Scoped to artifact: matchDetails carries CPEs, not purls,
                   but scoping costs nothing and cannot pick the wrong one. */
                const char *art = strstr(start, "\"artifact\"");
                purl_ecosystem(art ? art : start, e->eco, sizeof e->eco);
            }

            free(id);
            free(sev);
            free(pkg);
            free(ver);

            p[1] = save;
            start = NULL;
            continue;
        }

        if (*p == ']' && depth == 0)
        {
            closed = true;
            break;
        }
    }

    free(doc);

    if (!closed)
        die("%s: truncated or malformed — the matches array never closes "
            "(%zu findings read before the end of the file)",
            path, n);

    /*
     * Unlike an SBOM with no packages, a report with no findings is a real
     * and welcome result. Say nothing and return zero.
     */
    size_t unique = n ? dedupe(vs, n) : 0;
    if (unique != n)
        fprintf(stderr, "  %s: %zu findings, %zu after deduplication\n",
                path, n, unique);

    *out = vs;
    return unique;
}

static int cmp_vuln(const void *x, const void *y)
{
    const struct vuln *a = x, *b = y;
    int c = strcmp(a->id, b->id);
    if (c)
        return c;
    c = strcmp(a->package, b->package);
    return c ? c : strcmp(a->version, b->version);
}

/*
 * grype reports one finding per matcher that fired, so the same CVE against
 * the same package arrives more than once — through the distro feed and
 * through an NVD CPE match, say. Counting both would inflate every total.
 */
static size_t dedupe(struct vuln *v, size_t n)
{
    if (n < 2)
        return n;

    qsort(v, n, sizeof *v, cmp_vuln);

    size_t w = 1;
    for (size_t i = 1; i < n; i++)
        if (cmp_vuln(&v[i], &v[w - 1]) != 0)
            v[w++] = v[i];

    return w;
}
