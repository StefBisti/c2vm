#include "custody/verify.h"
#include "core/json.h"
#include "core/run.h"
#include "core/util.h"
#include "custody/publish.h"
#include "custody/vuln.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct policy
{
    char identity[256];
    char issuer[256];
    long max_critical; /* -1: unlimited */
    long max_high;
};

static void verify_usage(void)
{
    fputs(
        "usage: c2vm verify <oci-ref> [options]\n"
        "\n"
        "  --policy <file>    identity and CVE limits (default: policy/default.yaml)\n"
        "  --cosign <path>    cosign binary (default: found on PATH)\n"
        "  --oras <path>      oras binary (default: found on PATH)\n"
        "  --grype <path>     grype binary (default: found on PATH)\n",
        stderr);
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;

    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
                       end[-1] == '"' || end[-1] == '\''))
        *--end = '\0';

    if (*s == '"' || *s == '\'')
        s++;
    return s;
}

// loads the policy from the yml file
static void policy_load(const char *path, struct policy *p)
{
    p->identity[0] = p->issuer[0] = '\0';
    p->max_critical = p->max_high = -1;

    char *doc = json_slurp(path);

    for (char *line = strtok(doc, "\n"); line; line = strtok(NULL, "\n"))
    {
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';

        char *key = trim(line);
        char *val = trim(colon + 1);
        if (!*key || !*val)
            continue;

        if (!strcmp(key, "identity"))
            snprintf(p->identity, sizeof p->identity, "%s", val);
        else if (!strcmp(key, "issuer"))
            snprintf(p->issuer, sizeof p->issuer, "%s", val);
        else if (!strcmp(key, "max_critical"))
            p->max_critical = strtol(val, NULL, 10);
        else if (!strcmp(key, "max_high"))
            p->max_high = strtol(val, NULL, 10);
    }

    free(doc);

    die_if(!p->identity[0] || !p->issuer[0], "%s must set both 'identity' and 'issuer'", path);
}

static void report(const char *what, bool ok, const char *detail)
{
    fprintf(stderr, "  %s %-28s %s\n", ok ? "ok  " : "FAIL", what, detail ? detail : "");
}

static int cosign_run(const char *cosign, const struct policy *pol, const char *subject,
                      const char *sub, const char *type, char **out)
{
    char *argv[12];
    size_t n = 0;

    argv[n++] = (char *)cosign;
    argv[n++] = (char *)sub;
    if (type)
    {
        argv[n++] = "--type";
        argv[n++] = (char *)type;
    }
    argv[n++] = "--certificate-identity";
    argv[n++] = (char *)pol->identity;
    argv[n++] = "--certificate-oidc-issuer";
    argv[n++] = (char *)pol->issuer;
    argv[n++] = (char *)subject;
    argv[n] = NULL;

    char *captured = NULL;
    int rc = run_argv_capture(argv, &captured);

    if (out && rc == 0)
        *out = captured;
    else
        free(captured);

    return rc;
}

// checks attestation and returns in-toto statement
static char *attestation(const char *cosign, const struct policy *pol, const char *subject, const char *type)
{
    char *env = NULL;
    if (cosign_run(cosign, pol, subject, "verify-attestation", type, &env) != 0)
        return NULL;

    char *payload = json_get(env, "payload");
    free(env);
    if (!payload)
        return NULL;

    char *statement = base64_decode(payload, NULL);
    free(payload);
    return statement;
}

/*
 * Scans the SBOM the publisher signed - not one built locally - so the
 * severity counts are derived from the same bytes the attestation covers.
 */
static int cve_check(const char *grype, const struct policy *pol, const char *spdx_statement)
{
    char *spdx = json_object(spdx_statement, "predicate");
    if (!spdx)
    {
        report("cve policy", false, "SBOM attestation has no predicate");
        return 1;
    }

    char sbom[PATH_MAX], reportfile[PATH_MAX];
    snprintf(sbom, sizeof sbom, "/tmp/c2vm-verify-%d.spdx.json", (int)getpid());
    snprintf(reportfile, sizeof reportfile, "/tmp/c2vm-verify-%d.cve.json", (int)getpid());

    write_file(sbom, "%s", spdx);
    free(spdx);

    grype_env();
    char *argv[] = {(char *)grype, (char *)P("sbom:%s", sbom), "-o", (char *)P("json=%s", reportfile), NULL};
    run_argv_ok(argv);

    struct vuln *vs = NULL;
    size_t n = vuln_load(reportfile, &vs);

    unlink(sbom);
    unlink(reportfile);

    long counts[SEVERITY_COUNT][2] = {{0}};
    for (size_t i = 0; i < n; i++)
    {
        int rank = severity_rank(vs[i].severity);
        counts[rank][0]++;
        if (!strcmp(vs[i].eco, "deb"))
            counts[rank][1]++;
    }
    free(vs);

    fprintf(stderr, "\n  %-12s %10s %10s\n", "severity", "all", "deb");
    for (int r = 0; r < SEVERITY_COUNT; r++)
        if (counts[r][0])
            fprintf(stderr, "  %-12s %10ld %10ld\n", severity_name(r), counts[r][0], counts[r][1]);
    fputc('\n', stderr);

    int failed = 0;
    const struct
    {
        const char *name;
        int rank;
        long max;
    } GATES[] = {
        {"critical", severity_rank("Critical"), pol->max_critical},
        {"high", severity_rank("High"), pol->max_high},
    };

    for (size_t i = 0; i < sizeof GATES / sizeof GATES[0]; i++)
    {
        long got = counts[GATES[i].rank][1];
        if (GATES[i].max < 0)
            continue;

        bool ok = got <= GATES[i].max;
        report(P("cve policy: %s", GATES[i].name), ok,
               P("%ld deb finding(s), limit %ld", got, GATES[i].max));
        failed += !ok;
    }

    return failed;
}

// main function
int cmd_verify(int argc, char *argv[])
{
    // start of parse opts
    const char *ref = NULL;
    const char *policy_path = "policy/default.yaml";
    const char *cosign_override = NULL, *oras_override = NULL, *grype_override = NULL;

    for (int i = 0; i < argc; i++)
    {
        const char *a = argv[i];

        if (!strcmp(a, "-h") || !strcmp(a, "--help"))
        {
            verify_usage();
            return EXIT_USAGE;
        }

        if (a[0] == '-')
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "c2vm: %s needs a value\n", a);
                return EXIT_USAGE;
            }
            const char *v = argv[++i];

            if (!strcmp(a, "--policy"))
                policy_path = v;
            else if (!strcmp(a, "--cosign"))
                cosign_override = v;
            else if (!strcmp(a, "--oras"))
                oras_override = v;
            else if (!strcmp(a, "--grype"))
                grype_override = v;
            else
            {
                fprintf(stderr, "c2vm: unknown option '%s'\n", a);
                return EXIT_USAGE;
            }
            continue;
        }

        if (ref)
        {
            fprintf(stderr, "c2vm: unexpected argument '%s'\n", a);
            return EXIT_USAGE;
        }
        ref = a;
    }

    if (!ref)
    {
        verify_usage();
        return EXIT_USAGE;
    }
    // end of parse opts

    struct policy pol;
    policy_load(policy_path, &pol);

    const char *cosign = tool_path("cosign", cosign_override);
    const char *oras = tool_path("oras", oras_override);
    const char *grype = tool_path("grype", grype_override);

    step("verifying %s", ref);
    fprintf(stderr, "  identity %s (%s)\n\n", pol.identity, pol.issuer);

    char *digest = oci_digest(oras, ref);
    const char *subject = P("%s@%s", ref, digest);

    char *manifest = NULL;
    char *fetch[] = {(char *)oras, "manifest", "fetch", (char *)ref, NULL};
    die_if(run_argv_capture(fetch, &manifest) != 0, "cannot fetch the manifest for %s", ref);

    int failed = 0;

    // signed by the identity in the policy
    bool signed_ok = cosign_run(cosign, &pol, subject, "verify", NULL, NULL) == 0;
    report("signature", signed_ok, digest);
    failed += !signed_ok;

    // both attestations, both under the same identity
    char *spdx_stmt = attestation(cosign, &pol, subject, "spdxjson");
    report("sbom attestation", spdx_stmt != NULL, "https://spdx.dev/Document");
    failed += !spdx_stmt;

    char *custom_stmt = attestation(cosign, &pol, subject, "custom");
    report("conversion attestation", custom_stmt != NULL, "https://c2vm.dev/conversion/v1");
    failed += !custom_stmt;

    // check digests
    if (custom_stmt)
    {
        /* cosign's "custom" type stores the predicate as an escaped string;
           json_get unescapes it, so it parses as a document in its own right. */
        char *inner = json_get(custom_stmt, "Data");

        char *layer = json_get_in(manifest, "layers", "digest");
        char *subj = inner ? json_get_in(inner, "subject", "sha256") : NULL;

        bool bound = layer && subj && !strcmp(layer + 7, subj); /* skip "sha256:" */
        report("disk digest binding", bound, subj ? subj : "no subject digest");
        failed += !bound;

        char *claimed = inner ? json_get_in(inner, "source", "digest") : NULL;
        char *annotated = json_get(manifest, "dev.c2vm.source-digest");
        bool src_ok = claimed && annotated && !strcmp(claimed, annotated);
        report("source image", src_ok, claimed ? claimed : "no source digest");
        failed += !src_ok;

        if (inner)
        {
            char *image = json_get_in(inner, "source", "image");
            char *kver = json_get_in(inner, "kernel", "version");
            char *built = json_get_in(inner, "builder", "built_at");
            fprintf(stderr, "\n  %s -> kernel %s, built %s\n", image ? image : "?",
                    kver ? kver : "?", built ? built : "?");
            free(image);
            free(kver);
            free(built);
        }

        free(layer);
        free(subj);
        free(claimed);
        free(annotated);
        free(inner);
    }

    // grype over the signed sbom
    if (spdx_stmt)
        failed += cve_check(grype, &pol, spdx_stmt);

    free(spdx_stmt);
    free(custom_stmt);
    free(manifest);
    free(digest);

    if (failed)
    {
        fprintf(stderr, "\n%d check(s) failed\n", failed);
        return EXIT_POLICY;
    }

    fputs("\nall checks passed\n", stderr);
    return EXIT_SUCCESS;
}
