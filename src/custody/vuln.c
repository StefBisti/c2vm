#include "custody/vuln.h"
#include "core/json.h"
#include "core/run.h"
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

size_t vuln_load(const char *path, struct vuln **out)
{
    char *doc = json_slurp(path);

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
            p = (char *)json_skip_string(p) - 1;
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

                // scoped to artifact
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
    {
        die("%s: truncated or malformed, the matches array never closes (%zu findings read before the end of the file)", path, n);
    }
    size_t unique = n ? dedupe_sorted(vs, n, sizeof *vs, cmp_vuln) : 0;
    if (unique != n)
    {
        fprintf(stderr, "  %s: %zu findings, %zu after deduplication\n", path, n, unique);
    }
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
