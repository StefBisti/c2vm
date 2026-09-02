#include "custody/diff.h"
#include "core/json.h"
#include "core/run.h"
#include "custody/sbom.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_USAGE 2
#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

struct change
{
    struct pkg from;
    struct pkg to;
};

struct diff_opts
{
    const char *a;
    const char *b;
    const char *results;
};


static const struct
{
    const char *group;
    const char *prefixes[6];
} GROUPS[] = {
    {"kernel", {"linux-", "initramfs", "kmod", "firmware", NULL}},
    {"bootloader", {"grub", "efibootmgr", "shim", "mokutil", "os-prober", NULL}},
    {"init", {"systemd", "init", "udev", "dbus", "libnss-systemd", NULL}},
    {"networking", {"netplan", "iproute2", "isc-dhcp", "ifupdown", "openssh", "resolvconf"}},
    {"cloud-init", {"cloud-init", "python3-", "cloud-guest", NULL}},
};

static const char *classify(const char *name)
{
    for (size_t g = 0; g < NELEMS(GROUPS); g++)
        for (size_t i = 0; i < NELEMS(GROUPS[g].prefixes); i++)
        {
            const char *pre = GROUPS[g].prefixes[i];
            if (!pre)
                break;
            if (!strncmp(name, pre, strlen(pre)))
                return GROUPS[g].group;
        }
    return "dependency";
}

/* Full identity: two entries are the same package only if the version agrees. */
static int cmp_full(const void *x, const void *y)
{
    const struct pkg *a = x, *b = y;
    int c = strcmp(a->eco, b->eco);
    if (c)
        return c;
    c = strcmp(a->name, b->name);
    if (c)
        return c;
    return strcmp(a->version, b->version);
}

/* Identity ignoring version, which is how a version change is recognised. */
static int cmp_name(const struct pkg *a, const struct pkg *b)
{
    int c = strcmp(a->eco, b->eco);
    return c ? c : strcmp(a->name, b->name);
}

static void diff_usage(void)
{
    fputs(
        "usage: c2vm diff <sbom-a> <sbom-b> [options]\n"
        "\n"
        "  --results <dir>    where the report is written (default: results)\n"
        "\n"
        "Both inputs must be SPDX JSON. <sbom-a> is the baseline: packages\n"
        "only in <sbom-b> are reported as added.\n",
        stderr);
}

/* Every ecosystem seen in either document, so the report has stable rows. */
static size_t collect_ecos(const struct pkg *a, size_t na,
                           const struct pkg *b, size_t nb,
                           const char *ecos[], size_t cap)
{
    size_t n = 0;

    for (int pass = 0; pass < 2; pass++)
    {
        const struct pkg *p = pass ? b : a;
        size_t count = pass ? nb : na;

        for (size_t i = 0; i < count; i++)
        {
            bool seen = false;
            for (size_t j = 0; j < n; j++)
                if (!strcmp(ecos[j], p[i].eco))
                    seen = true;

            if (!seen && n < cap)
                ecos[n++] = p[i].eco;
        }
    }
    return n;
}

static void write_json(const struct diff_opts *o,
                       const struct pkg *added, size_t nadd,
                       const struct pkg *removed, size_t nrem,
                       const struct change *changed, size_t nchg,
                       size_t nunch, size_t na, size_t nb,
                       const char *ecos[], size_t neco,
                       const struct pkg *a, const struct pkg *b)
{
    const char *path = P("%s/sbom-diff.json", o->results);
    fprintf(stderr, "  > %s\n", path);

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

    fprintf(f, "{\n");
    fprintf(f, "  \"a\": { \"path\": \"%s\", \"packages\": %zu },\n", J(o->a), na);
    fprintf(f, "  \"b\": { \"path\": \"%s\", \"packages\": %zu },\n", J(o->b), nb);
    fprintf(f, "  \"summary\": { \"added\": %zu, \"removed\": %zu, "
               "\"changed\": %zu, \"unchanged\": %zu },\n",
            nadd, nrem, nchg, nunch);

    fprintf(f, "  \"by_ecosystem\": {\n");
    for (size_t e = 0; e < neco; e++)
    {
        size_t ia = 0, ib = 0, ad = 0, rm = 0;
        for (size_t i = 0; i < na; i++)
            if (!strcmp(a[i].eco, ecos[e]))
                ia++;
        for (size_t i = 0; i < nb; i++)
            if (!strcmp(b[i].eco, ecos[e]))
                ib++;
        for (size_t i = 0; i < nadd; i++)
            if (!strcmp(added[i].eco, ecos[e]))
                ad++;
        for (size_t i = 0; i < nrem; i++)
            if (!strcmp(removed[i].eco, ecos[e]))
                rm++;

        fprintf(f, "    \"%s\": { \"a\": %zu, \"b\": %zu, \"added\": %zu, "
                   "\"removed\": %zu }%s\n",
                J(ecos[e]), ia, ib, ad, rm, e + 1 < neco ? "," : "");
    }
    fprintf(f, "  },\n");

    fprintf(f, "  \"added\": [\n");
    for (size_t i = 0; i < nadd; i++)
        fprintf(f, "    { \"name\": \"%s\", \"version\": \"%s\", "
                   "\"ecosystem\": \"%s\", \"group\": \"%s\" }%s\n",
                J(added[i].name), J(added[i].version), J(added[i].eco),
                J(classify(added[i].name)), i + 1 < nadd ? "," : "");
    fprintf(f, "  ],\n");

    fprintf(f, "  \"removed\": [\n");
    for (size_t i = 0; i < nrem; i++)
        fprintf(f, "    { \"name\": \"%s\", \"version\": \"%s\", "
                   "\"ecosystem\": \"%s\" }%s\n",
                J(removed[i].name), J(removed[i].version), J(removed[i].eco),
                i + 1 < nrem ? "," : "");
    fprintf(f, "  ],\n");

    fprintf(f, "  \"changed\": [\n");
    for (size_t i = 0; i < nchg; i++)
        fprintf(f, "    { \"name\": \"%s\", \"ecosystem\": \"%s\", "
                   "\"from\": \"%s\", \"to\": \"%s\" }%s\n",
                J(changed[i].from.name), J(changed[i].from.eco),
                J(changed[i].from.version), J(changed[i].to.version),
                i + 1 < nchg ? "," : "");
    fprintf(f, "  ]\n}\n");

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

static void write_markdown(const struct diff_opts *o,
                           const struct pkg *added, size_t nadd,
                           const struct pkg *removed, size_t nrem,
                           const struct change *changed, size_t nchg,
                           size_t nunch, size_t na, size_t nb,
                           const char *ecos[], size_t neco,
                           const struct pkg *a, const struct pkg *b)
{
    const char *path = P("%s/sbom-diff.md", o->results);
    fprintf(stderr, "  > %s\n", path);

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

    fprintf(f, "# SBOM delta\n\n");
    fprintf(f, "- baseline: `%s` (%zu packages)\n", o->a, na);
    fprintf(f, "- result:   `%s` (%zu packages)\n\n", o->b, nb);

    fprintf(f, "| | count |\n|---|---|\n");
    fprintf(f, "| added | %zu |\n| removed | %zu |\n"
               "| version changed | %zu |\n| unchanged | %zu |\n\n",
            nadd, nrem, nchg, nunch);

    fprintf(f, "## By ecosystem\n\n");
    fprintf(f, "| ecosystem | baseline | result | added | removed |\n");
    fprintf(f, "|---|---|---|---|---|\n");
    for (size_t e = 0; e < neco; e++)
    {
        size_t ia = 0, ib = 0, ad = 0, rm = 0;
        for (size_t i = 0; i < na; i++)
            if (!strcmp(a[i].eco, ecos[e]))
                ia++;
        for (size_t i = 0; i < nb; i++)
            if (!strcmp(b[i].eco, ecos[e]))
                ib++;
        for (size_t i = 0; i < nadd; i++)
            if (!strcmp(added[i].eco, ecos[e]))
                ad++;
        for (size_t i = 0; i < nrem; i++)
            if (!strcmp(removed[i].eco, ecos[e]))
                rm++;
        fprintf(f, "| %s | %zu | %zu | %zu | %zu |\n",
                ecos[e], ia, ib, ad, rm);
    }

    /* Only deb additions get grouped by function: the others are kernel
       modules and vendored Python, which no functional bucket describes. */
    fprintf(f, "\n## Added `pkg:deb` packages, by function\n\n");

    static const char *ORDER[] = {"kernel", "bootloader", "init",
                                  "networking", "cloud-init", "dependency"};
    for (size_t g = 0; g < NELEMS(ORDER); g++)
    {
        size_t count = 0;
        for (size_t i = 0; i < nadd; i++)
            if (!strcmp(added[i].eco, "deb") &&
                !strcmp(classify(added[i].name), ORDER[g]))
                count++;

        if (count == 0)
            continue;

        fprintf(f, "### %s (%zu)\n\n", ORDER[g], count);
        for (size_t i = 0; i < nadd; i++)
            if (!strcmp(added[i].eco, "deb") &&
                !strcmp(classify(added[i].name), ORDER[g]))
                fprintf(f, "- `%s` %s\n", added[i].name, added[i].version);
        fprintf(f, "\n");
    }

    if (nchg)
    {
        fprintf(f, "## Version changed\n\n| package | from | to |\n|---|---|---|\n");
        for (size_t i = 0; i < nchg; i++)
            fprintf(f, "| `%s` | %s | %s |\n", changed[i].from.name,
                    changed[i].from.version, changed[i].to.version);
        fprintf(f, "\n");
    }

    if (nrem)
    {
        fprintf(f, "## Removed\n\n");
        for (size_t i = 0; i < nrem; i++)
            fprintf(f, "- `%s` %s\n", removed[i].name, removed[i].version);
    }

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

int cmd_diff(int argc, char *argv[])
{
    struct diff_opts o = {NULL, NULL, "results"};

    for (int i = 0; i < argc; i++)
    {
        const char *arg = argv[i];

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
        {
            diff_usage();
            return EXIT_SUCCESS;
        }

        if (arg[0] == '-')
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "c2vm diff: %s needs a value\n", arg);
                return EXIT_USAGE;
            }
            if (!strcmp(arg, "--results"))
                o.results = argv[++i];
            else
            {
                fprintf(stderr, "c2vm diff: unknown option '%s'\n", arg);
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
            fprintf(stderr, "c2vm diff: unexpected argument '%s'\n", arg);
            return EXIT_USAGE;
        }
    }

    if (!o.a || !o.b)
    {
        fprintf(stderr, "c2vm diff: two SBOMs are required\n");
        diff_usage();
        return EXIT_USAGE;
    }

    struct pkg *a = NULL, *b = NULL;
    size_t na = sbom_load(o.a, &a);
    size_t nb = sbom_load(o.b, &b);

    step("comparing %zu against %zu packages", na, nb);

    qsort(a, na, sizeof *a, cmp_full);
    qsort(b, nb, sizeof *b, cmp_full);

    struct pkg *only_a = malloc(na * sizeof *only_a);
    struct pkg *only_b = malloc(nb * sizeof *only_b);
    if (!only_a || !only_b)
        die("out of memory");

    size_t noa = 0, nob = 0, nunch = 0;

    // Identical (name, version, ecosystem) on both sides is unchanged
    for (size_t i = 0, j = 0; i < na || j < nb;)
    {
        if (i == na)
            only_b[nob++] = b[j++];
        else if (j == nb)
            only_a[noa++] = a[i++];
        else
        {
            int c = cmp_full(&a[i], &b[j]);
            if (c < 0)
                only_a[noa++] = a[i++];
            else if (c > 0)
                only_b[nob++] = b[j++];
            else
            {
                nunch++;
                i++;
                j++;
            }
        }
    }

    // A name present on both sides with a different version is a change
    struct pkg *added = malloc((nob + 1) * sizeof *added);
    struct pkg *removed = malloc((noa + 1) * sizeof *removed);
    struct change *changed = malloc((noa + nob + 1) * sizeof *changed);
    if (!added || !removed || !changed)
        die("out of memory");

    size_t nadd = 0, nrem = 0, nchg = 0;

    for (size_t i = 0, j = 0; i < noa || j < nob;)
    {
        if (i == noa)
            added[nadd++] = only_b[j++];
        else if (j == nob)
            removed[nrem++] = only_a[i++];
        else
        {
            int c = cmp_name(&only_a[i], &only_b[j]);
            if (c < 0)
                removed[nrem++] = only_a[i++];
            else if (c > 0)
                added[nadd++] = only_b[j++];
            else
            {
                changed[nchg].from = only_a[i++];
                changed[nchg].to = only_b[j++];
                nchg++;
            }
        }
    }

    const char *ecos[32];
    size_t neco = collect_ecos(a, na, b, nb, ecos, NELEMS(ecos));

    run_ok("mkdir", "-p", o.results, NULL);

    write_json(&o, added, nadd, removed, nrem, changed, nchg, nunch, na, nb, ecos, neco, a, b);
    write_markdown(&o, added, nadd, removed, nrem, changed, nchg, nunch, na, nb, ecos, neco, a, b);

    fprintf(stderr, "\n  added:     %zu\n", nadd);
    fprintf(stderr, "  removed:   %zu\n", nrem);
    fprintf(stderr, "  changed:   %zu\n", nchg);
    fprintf(stderr, "  unchanged: %zu\n", nunch);
    for (size_t e = 0; e < neco; e++)
    {
        size_t ad = 0;
        for (size_t i = 0; i < nadd; i++)
            if (!strcmp(added[i].eco, ecos[e]))
                ad++;
        fprintf(stderr, "    %-10s +%zu\n", ecos[e], ad);
    }

    free(a);
    free(b);
    free(only_a);
    free(only_b);
    free(added);
    free(removed);
    free(changed);

    return EXIT_SUCCESS;
}
