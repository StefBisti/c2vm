#include "custody/vuln.h"
#include "core/json.h"
#include "core/util.h"
#include "custody/sbom.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int cmp_vuln(const void *x, const void *y);

static const char *SEVERITIES[SEVERITY_COUNT] = {
    "Critical", "High", "Medium", "Low", "Negligible", "Unknown"};

int severity_rank(const char *severity)
{
    for (size_t i = 0; i < NELEMS(SEVERITIES); i++)
        if (!strcmp(severity, SEVERITIES[i]))
            return (int)i;
    return SEVERITY_COUNT - 1;
}

const char *severity_name(int rank)
{
    if (rank < 0 || rank >= SEVERITY_COUNT)
        return "Unknown";
    return SEVERITIES[rank];
}

// reads a grype JSON report and returns an array of {id, severity, package, version, ecosystem}
void grype_env(void)
{
    setenv("GRYPE_DB_AUTO_UPDATE", "false", 1);
    setenv("GRYPE_DB_VALIDATE_AGE", "false", 1);

    if (geteuid() != 0)
        return;

    const char *user = getenv("SUDO_USER");
    if (!user)
        return;

    const char *cache = P("/home/%s/.cache/grype/db", user);
    if (access(cache, R_OK) == 0)
        setenv("GRYPE_DB_CACHE_DIR", cache, 1);
}

struct vuln_acc
{
    struct vuln *v;
    size_t n, cap;
};

static void collect_vuln(const char *elem, void *ctx)
{
    struct vuln_acc *a = ctx;

    char *id = json_get_in(elem, "vulnerability", "id");
    char *sev = json_get_in(elem, "vulnerability", "severity");
    char *pkg = json_get_in(elem, "artifact", "name");
    char *ver = json_get_in(elem, "artifact", "version");

    if (id && sev && pkg)
    {
        if (a->n == a->cap)
            a->v = xrealloc(a->v, (a->cap *= 2) * sizeof *a->v);

        struct vuln *e = &a->v[a->n++];
        snprintf(e->id, sizeof e->id, "%s", id);
        snprintf(e->severity, sizeof e->severity, "%s", sev);
        snprintf(e->package, sizeof e->package, "%s", pkg);
        snprintf(e->version, sizeof e->version, "%s", ver ? ver : "");

        // scoped to artifact
        const char *art = strstr(elem, "\"artifact\"");
        purl_ecosystem(art ? art : elem, e->eco, sizeof e->eco);
    }

    free(id);
    free(sev);
    free(pkg);
    free(ver);
}

size_t vuln_load(const char *path, struct vuln **out)
{
    char *doc = json_slurp(path);

    die_if(!strstr(doc, "\"matches\""), "%s has no \"matches\" array; is it a grype JSON report?", path);

    struct vuln_acc acc = {.cap = 256, .n = 0};
    acc.v = xmalloc(acc.cap * sizeof *acc.v);

    json_each_object(doc, path, "matches", collect_vuln, &acc);
    free(doc);

    size_t unique = acc.n ? dedupe_sorted(acc.v, acc.n, sizeof *acc.v, cmp_vuln) : 0;
    if (unique != acc.n)
        fprintf(stderr, "  %s: %zu findings, %zu after deduplication\n", path, acc.n, unique);

    *out = acc.v;
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
