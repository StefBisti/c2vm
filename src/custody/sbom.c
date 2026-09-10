#include "custody/sbom.h"
#include "core/json.h"
#include "core/util.h"

static int cmp_pkg(const void *x, const void *y);

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* purl looks like pkg:deb/ubuntu/zlib1g@1.3 — this lifts out "deb". */
void purl_ecosystem(const char *elem, char *out, size_t cap)
{
    snprintf(out, cap, "none");

    const char *purl = strstr(elem, "\"pkg:");
    if (!purl)
        return;

    purl += 5; /* past the quote and "pkg:" */
    size_t i = 0;
    while (purl[i] && purl[i] != '/' && purl[i] != '"' && i < cap - 1)
        i++;

    if (i == 0)
        return;

    snprintf(out, cap < i + 1 ? cap : i + 1, "%s", purl);
}

struct pkg_acc
{
    struct pkg *v;
    size_t n, cap;
};

static void collect_pkg(const char *elem, void *ctx)
{
    struct pkg_acc *a = ctx;

    char *name = json_get(elem, "name");
    char *ver = json_get(elem, "versionInfo");

    if (name)
    {
        if (a->n == a->cap)
            a->v = xrealloc(a->v, (a->cap *= 2) * sizeof *a->v);

        struct pkg *e = &a->v[a->n++];
        snprintf(e->name, sizeof e->name, "%s", name);
        snprintf(e->version, sizeof e->version, "%s", ver ? ver : "");
        purl_ecosystem(elem, e->eco, sizeof e->eco);
    }

    free(name);
    free(ver);
}

size_t sbom_load(const char *path, struct pkg **out)
{
    char *doc = json_slurp(path);

    struct pkg_acc acc = {.cap = 256, .n = 0};
    acc.v = xmalloc(acc.cap * sizeof *acc.v);

    json_each_object(doc, path, "packages", collect_pkg, &acc);
    free(doc);

    die_if(acc.n == 0, "%s: no packages found; is it an SPDX document?", path);

    size_t unique = dedupe_sorted(acc.v, acc.n, sizeof *acc.v, cmp_pkg);
    if (unique != acc.n)
        fprintf(stderr, "  %s: %zu entries, %zu after deduplication\n", path, acc.n, unique);

    *out = acc.v;
    return unique;
}

static int cmp_pkg(const void *x, const void *y)
{
    const struct pkg *a = x, *b = y;
    int c = strcmp(a->eco, b->eco);
    if (c)
        return c;
    c = strcmp(a->name, b->name);
    return c ? c : strcmp(a->version, b->version);
}

size_t sbom_count_eco(const struct pkg *p, size_t n, const char *eco)
{
    size_t c = 0;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(p[i].eco, eco))
            c++;
    return c;
}
