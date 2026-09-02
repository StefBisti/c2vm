#include "custody/cve.h"
#include "core/json.h"
#include "core/run.h"
#include "custody/vuln.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_USAGE 2
#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

/* How many packages the attribution table names before it stops. */
#define TOP_PACKAGES 15

struct cve_opts
{
    const char *a;
    const char *b;
    const char *results;
};

struct attribution
{
    char package[160];
    char eco[16];
    size_t count;
    size_t critical;
    size_t high;
};

static void cve_usage(void)
{
    fputs(
        "usage: c2vm cve <report-a> <report-b> [options]\n"
        "\n"
        "  --results <dir>    where the report is written (default: results)\n"
        "\n"
        "Both inputs must be grype JSON. <report-a> is the baseline:\n"
        "findings only in <report-b> are reported as new.\n",
        stderr);
}

// sort/compare key (id, package)
static int cmp_key(const struct vuln *a, const struct vuln *b)
{
    int c = strcmp(a->id, b->id);
    return c ? c : strcmp(a->package, b->package);
}

static int cmp_key_qsort(const void *x, const void *y)
{
    return cmp_key(x, y);
}

/* Most findings first; Critical breaks a tie */
static int cmp_attribution(const void *x, const void *y)
{
    const struct attribution *a = x, *b = y;
    if (a->count != b->count)
        return a->count < b->count ? 1 : -1;
    if (a->critical != b->critical)
        return a->critical < b->critical ? 1 : -1;
    return strcmp(a->package, b->package);
}

// [sev][0] = all , [sev][1] = deb only
static void tally(const struct vuln *v, size_t n, size_t out[SEVERITY_COUNT][2])
{
    memset(out, 0, sizeof(size_t) * SEVERITY_COUNT * 2);

    for (size_t i = 0; i < n; i++)
    {
        int r = severity_rank(v[i].severity);
        out[r][0]++;
        if (!strcmp(v[i].eco, "deb"))
            out[r][1]++;
    }
}

static size_t attribute(const struct vuln *v, size_t n, struct attribution **out)
{
    struct attribution *rows = malloc((n + 1) * sizeof *rows);
    if (!rows)
        die("out of memory");

    size_t nrows = 0;

    for (size_t i = 0; i < n; i++)
    {
        struct attribution *row = NULL;
        for (size_t j = 0; j < nrows; j++)
            if (!strcmp(rows[j].package, v[i].package) && !strcmp(rows[j].eco, v[i].eco))
                row = &rows[j];

        if (!row)
        {
            row = &rows[nrows++];
            snprintf(row->package, sizeof row->package, "%s", v[i].package);
            snprintf(row->eco, sizeof row->eco, "%s", v[i].eco);
            row->count = row->critical = row->high = 0;
        }

        row->count++;
        if (!strcmp(v[i].severity, "Critical"))
            row->critical++;
        else if (!strcmp(v[i].severity, "High"))
            row->high++;
    }

    qsort(rows, nrows, sizeof *rows, cmp_attribution);

    *out = rows;
    return nrows;
}

static void write_json(const struct cve_opts *o,
                       size_t na, size_t nb,
                       size_t ta[SEVERITY_COUNT][2],
                       size_t tb[SEVERITY_COUNT][2],
                       const struct vuln *new, size_t nnew,
                       const struct vuln *gone, size_t ngone,
                       size_t nshared,
                       const struct attribution *attr, size_t nattr)
{
    const char *path = P("%s/cve-diff.json", o->results);
    fprintf(stderr, "  > %s\n", path);

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

    fprintf(f, "{\n");
    fprintf(f, "  \"a\": { \"path\": \"%s\", \"findings\": %zu },\n", J(o->a), na);
    fprintf(f, "  \"b\": { \"path\": \"%s\", \"findings\": %zu },\n", J(o->b), nb);
    fprintf(f, "  \"summary\": { \"new\": %zu, \"gone\": %zu, \"shared\": %zu },\n", nnew, ngone, nshared);

    fprintf(f, "  \"by_severity\": {\n");
    for (int s = 0; s < SEVERITY_COUNT; s++)
        fprintf(f,
                "    \"%s\": { \"a\": %zu, \"b\": %zu, \"delta\": %lld,"
                " \"a_deb\": %zu, \"b_deb\": %zu, \"delta_deb\": %lld }%s\n",
                severity_name(s), ta[s][0], tb[s][0],
                (long long)tb[s][0] - (long long)ta[s][0],
                ta[s][1], tb[s][1],
                (long long)tb[s][1] - (long long)ta[s][1],
                s + 1 < SEVERITY_COUNT ? "," : "");
    fprintf(f, "  },\n");

    fprintf(f, "  \"introduced_by\": [\n");
    for (size_t i = 0; i < nattr; i++)
        fprintf(f,
                "    { \"package\": \"%s\", \"ecosystem\": \"%s\","
                " \"findings\": %zu, \"critical\": %zu, \"high\": %zu }%s\n",
                J(attr[i].package), J(attr[i].eco), attr[i].count,
                attr[i].critical, attr[i].high, i + 1 < nattr ? "," : "");
    fprintf(f, "  ],\n");

    fprintf(f, "  \"new\": [\n");
    for (size_t i = 0; i < nnew; i++)
        fprintf(f,
                "    { \"id\": \"%s\", \"severity\": \"%s\", \"package\": \"%s\","
                " \"version\": \"%s\", \"ecosystem\": \"%s\" }%s\n",
                J(new[i].id), J(new[i].severity), J(new[i].package),
                J(new[i].version), J(new[i].eco), i + 1 < nnew ? "," : "");
    fprintf(f, "  ],\n");

    fprintf(f, "  \"gone\": [\n");
    for (size_t i = 0; i < ngone; i++)
        fprintf(f,
                "    { \"id\": \"%s\", \"severity\": \"%s\", \"package\": \"%s\","
                " \"ecosystem\": \"%s\" }%s\n",
                J(gone[i].id), J(gone[i].severity), J(gone[i].package),
                J(gone[i].eco), i + 1 < ngone ? "," : "");
    fprintf(f, "  ]\n}\n");

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

static void write_markdown(const struct cve_opts *o,
                           size_t na, size_t nb,
                           size_t ta[SEVERITY_COUNT][2],
                           size_t tb[SEVERITY_COUNT][2],
                           const struct vuln *new, size_t nnew,
                           size_t ngone, size_t nshared,
                           const struct attribution *attr, size_t nattr)
{
    const char *path = P("%s/cve-diff.md", o->results);
    fprintf(stderr, "  > %s\n", path);

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

    fprintf(f, "# CVE delta\n\n");
    fprintf(f, "- baseline: `%s` (%zu findings)\n", o->a, na);
    fprintf(f, "- result:   `%s` (%zu findings)\n\n", o->b, nb);
    fprintf(f, "new: %zu · gone: %zu · shared: %zu\n\n", nnew, ngone, nshared);

    fprintf(f, "## By severity\n\n");
    fprintf(f, "| severity | source | disk | delta | source (deb) | disk (deb) | delta (deb) |\n");
    fprintf(f, "|---|---|---|---|---|---|---|\n");
    for (int s = 0; s < SEVERITY_COUNT; s++)
    {
        if (ta[s][0] == 0 && tb[s][0] == 0)
            continue;
        fprintf(f, "| %s | %zu | %zu | %+lld | %zu | %zu | %+lld |\n",
                severity_name(s), ta[s][0], tb[s][0],
                (long long)tb[s][0] - (long long)ta[s][0],
                ta[s][1], tb[s][1],
                (long long)tb[s][1] - (long long)ta[s][1]);
    }

    fprintf(f, "\n## What introduced the new findings\n\n");
    fprintf(f, "| package | ecosystem | new findings | critical | high |\n");
    fprintf(f, "|---|---|---|---|---|\n");
    for (size_t i = 0; i < nattr && i < TOP_PACKAGES; i++)
        fprintf(f, "| `%s` | %s | %zu | %zu | %zu |\n", attr[i].package, attr[i].eco, attr[i].count, attr[i].critical, attr[i].high);
    if (nattr > TOP_PACKAGES)
        fprintf(f, "\n%zu further packages contributed fewer findings each.\n", nattr - TOP_PACKAGES);

    fprintf(f, "\n## New Critical and High findings\n\n");
    fprintf(f, "| CVE | severity | package | ecosystem |\n|---|---|---|---|\n");

    size_t shown = 0;
    for (int want = 0; want <= 1; want++)
        for (size_t i = 0; i < nnew; i++)
            if (severity_rank(new[i].severity) == want)
            {
                fprintf(f, "| %s | %s | `%s` | %s |\n", new[i].id,
                        new[i].severity, new[i].package, new[i].eco);
                shown++;
            }

    if (shown == 0)
        fprintf(f, "\nNone.\n");

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

int cmd_cve(int argc, char *argv[])
{
    struct cve_opts o = {NULL, NULL, "results"};

    for (int i = 0; i < argc; i++)
    {
        const char *arg = argv[i];

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
        {
            cve_usage();
            return EXIT_SUCCESS;
        }

        if (arg[0] == '-')
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "c2vm cve: %s needs a value\n", arg);
                return EXIT_USAGE;
            }
            if (!strcmp(arg, "--results"))
                o.results = argv[++i];
            else
            {
                fprintf(stderr, "c2vm cve: unknown option '%s'\n", arg);
                return EXIT_USAGE;
            }
            continue;
        }

        if (!o.a)
            o.a = arg;
        else if (!o.b)
            o.b = arg;
        else
        {
            fprintf(stderr, "c2vm cve: unexpected argument '%s'\n", arg);
            return EXIT_USAGE;
        }
    }

    if (!o.a || !o.b)
    {
        fprintf(stderr, "c2vm cve: two grype reports are required\n");
        cve_usage();
        return EXIT_USAGE;
    }

    struct vuln *a = NULL, *b = NULL;
    size_t na = vuln_load(o.a, &a);
    size_t nb = vuln_load(o.b, &b);

    step("comparing %zu against %zu findings", na, nb);

    qsort(a, na, sizeof *a, cmp_key_qsort);
    qsort(b, nb, sizeof *b, cmp_key_qsort);

    struct vuln *new = malloc((nb + 1) * sizeof *new);
    struct vuln *gone = malloc((na + 1) * sizeof *gone);
    if (!new || !gone)
        die("out of memory");

    size_t nnew = 0, ngone = 0, nshared = 0;

    for (size_t i = 0, j = 0; i < na || j < nb;)
    {
        if (i == na)
            new[nnew++] = b[j++];
        else if (j == nb)
            gone[ngone++] = a[i++];
        else
        {
            int c = cmp_key(&a[i], &b[j]);
            if (c < 0)
                gone[ngone++] = a[i++];
            else if (c > 0)
                new[nnew++] = b[j++];
            else
            {
                nshared++;
                i++;
                j++;
            }
        }
    }

    size_t ta[SEVERITY_COUNT][2], tb[SEVERITY_COUNT][2];
    tally(a, na, ta);
    tally(b, nb, tb);

    struct attribution *attr = NULL;
    size_t nattr = attribute(new, nnew, &attr);

    run_ok("mkdir", "-p", o.results, NULL);
    write_json(&o, na, nb, ta, tb, new, nnew, gone, ngone, nshared, attr, nattr);
    write_markdown(&o, na, nb, ta, tb, new, nnew, ngone, nshared, attr, nattr);

    fprintf(stderr, "\n  new:    %zu\n  gone:   %zu\n  shared: %zu\n", nnew, ngone, nshared);
    fprintf(stderr, "\n  %-11s %8s %8s %8s   %8s %8s\n", "severity", "source", "disk", "delta", "src deb", "disk deb");
    for (int s = 0; s < SEVERITY_COUNT; s++)
    {
        if (ta[s][0] == 0 && tb[s][0] == 0)
            continue;
        fprintf(stderr, "  %-11s %8zu %8zu %+8lld   %8zu %8zu\n",
                severity_name(s), ta[s][0], tb[s][0],
                (long long)tb[s][0] - (long long)ta[s][0],
                ta[s][1], tb[s][1]);
    }

    if (nattr)
        fprintf(stderr, "\n  largest contributor: %s (%zu findings)\n", attr[0].package, attr[0].count);

    free(a);
    free(b);
    free(new);
    free(gone);
    free(attr);

    return EXIT_SUCCESS;
}
