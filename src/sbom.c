#include "sbom.h"
#include "json.h"
#include "run.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static size_t dedupe(struct pkg *p, size_t n);

/* Whole file, sized by stat: these run to 8 MB and read_file() wants a cap. */
static char *slurp(const char *path, size_t *len)
{
    struct stat st;
    if (stat(path, &st) != 0)
        die("cannot stat %s: %s", path, strerror(errno));

    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot read %s: %s", path, strerror(errno));

    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf)
        die("out of memory reading %s (%lld bytes)", path, (long long)st.st_size);

    size_t got = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);

    buf[got] = '\0';
    *len = got;
    return buf;
}

// A package description containing { would break the brace counter.
// So when the walk hits a ", it skips the entire string:
static const char *skip_string(const char *p)
{
    p++; /* opening quote */
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

/* purl looks like pkg:deb/ubuntu/zlib1g@1.3 — this lifts out "deb". */
static void ecosystem_of(const char *elem, char *out, size_t cap)
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
// reads SPDX file and returns plain array of {name, version, ecosystem}, dups removed
size_t sbom_load(const char *path, struct pkg **out)
{
    size_t len = 0;
    char *doc = slurp(path, &len);

    char *key = strstr(doc, "\"packages\"");
    if (!key)
        die("%s has no \"packages\" array", path);

    char *p = strchr(key + strlen("\"packages\""), '[');
    if (!p)
        die("%s: \"packages\" is not an array", path);
    p++;

    size_t cap = 256, n = 0;
    struct pkg *pkgs = malloc(cap * sizeof *pkgs);
    if (!pkgs)
        die("out of memory");

    int depth = 0;
    char *start = NULL;
    bool closed = false; // did the packages array actually end?

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

            /* Terminate the element in place, read it, put the byte back. */
            char save = p[1];
            p[1] = '\0';

            char *name = json_get(start, "name");
            char *ver = json_get(start, "versionInfo");

            if (name)
            {
                if (n == cap)
                {
                    cap *= 2;
                    struct pkg *grown = realloc(pkgs, cap * sizeof *pkgs);
                    if (!grown)
                        die("out of memory");
                    pkgs = grown;
                }

                struct pkg *e = &pkgs[n++];
                snprintf(e->name, sizeof e->name, "%s", name);
                snprintf(e->version, sizeof e->version, "%s", ver ? ver : "");
                ecosystem_of(start, e->eco, sizeof e->eco);
            }

            free(name);
            free(ver);

            p[1] = save;
            start = NULL;
            continue;
        }

        /* The array's own closing bracket, at depth 0, ends the walk. */
        if (*p == ']' && depth == 0)
        {
            closed = true;
            break;
        }
    }

    free(doc);

    if (!closed)
        die("%s: truncated or malformed — the packages array never closes "
            "(%zu entries read before the end of the file)",
            path, n);

    if (n == 0)
        die("%s: no packages found; is it an SPDX document?", path);

    size_t unique = dedupe(pkgs, n);
    if (unique != n)
        fprintf(stderr, "  %s: %zu entries, %zu after deduplication\n", path, n, unique);

    *out = pkgs;
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

// sort-then-squeeze
static size_t dedupe(struct pkg *p, size_t n)
{
    if (n < 2)
        return n;

    qsort(p, n, sizeof *p, cmp_pkg);

    size_t w = 1;
    for (size_t i = 1; i < n; i++)
        if (cmp_pkg(&p[i], &p[w - 1]) != 0)
            p[w++] = p[i];

    return w;
}

size_t sbom_count_eco(const struct pkg *p, size_t n, const char *eco)
{
    size_t c = 0;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(p[i].eco, eco))
            c++;
    return c;
}
