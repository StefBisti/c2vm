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

/*
 * The consuming end of the chain. Everything the other commands recorded is
 * now on a registry and signed; this reads it back holding nothing but a
 * reference, which is the only test that proves the custody actually
 * transfers. The 600 MB disk is never downloaded: every claim lives in the
 * manifest and the two attestations.
 */

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

/*
 * A four-key subset of YAML, read line by line. A parser is not worth a
 * dependency here: the policy is two identity strings and two integers, and
 * the first colon always separates key from value even when the value is a
 * URL that contains one.
 */
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

    if (!p->identity[0] || !p->issuer[0])
        die("%s must set both 'identity' and 'issuer'", path);
}

static void report(const char *what, bool ok, const char *detail)
{
    fprintf(stderr, "  %s %-28s %s\n", ok ? "ok  " : "FAIL", what, detail ? detail : "");
}

/*
 * Runs one cosign subcommand under the policy's identity constraints. The
 * identity flags are the whole point: without them cosign will happily
 * confirm that *somebody* signed this.
 */
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

/* Verifies one attestation and returns its in-toto statement, or NULL. */
static char *attestation(const char *cosign, const struct policy *pol, const char *subject,
                         const char *type)
{
    char *env = NULL;
    if (cosign_run(cosign, pol, subject, "verify-attestation", type, &env) != 0)
        return NULL;

    /* A DSSE envelope: the statement is one base64 field of it. */
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
    char *argv[] = {(char *)grype, (char *)P("sbom:%s", sbom), "-o",
                    (char *)P("json=%s", reportfile), NULL};
    run_argv_ok(argv);

    struct vuln *vs = NULL;
    size_t n = vuln_load(reportfile, &vs);

    unlink(sbom);
    unlink(reportfile);

    /* Two columns, as c2vm cve reports them: every ecosystem, and the deb
       packages the conversion actually installed. NVD matches the kernel by
       CPE against every CVE ever filed against it, so the all-ecosystem
       number is an order of magnitude larger and is not what a policy on
       this project's own output should gate. */
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

int cmd_verify(int argc, char *argv[])
{
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
    if (run_argv_capture(fetch, &manifest) != 0)
        die("cannot fetch the manifest for %s", ref);

    int failed = 0;

    /* 1. Signed, by the identity the policy names. */
    bool signed_ok = cosign_run(cosign, &pol, subject, "verify", NULL, NULL) == 0;
    report("signature", signed_ok, digest);
    failed += !signed_ok;

    /* 2/3. Both attestations, each verified under the same identity. */
    char *spdx_stmt = attestation(cosign, &pol, subject, "spdxjson");
    report("sbom attestation", spdx_stmt != NULL, "https://spdx.dev/Document");
    failed += !spdx_stmt;

    char *custom_stmt = attestation(cosign, &pol, subject, "custom");
    report("conversion attestation", custom_stmt != NULL, "https://c2vm.dev/conversion/v1");
    failed += !custom_stmt;

    /*
     * 4/5. The two bindings that make the attestation about *this* artifact.
     * cosign's own subject is the manifest digest, so on its own it says
     * nothing about the bytes inside; the conversion statement names the disk
     * hash, and that must be the layer the registry is serving.
     */
    if (custom_stmt)
    {
        /* cosign's "custom" type stores the predicate as an escaped string. */
        char *data = json_get(custom_stmt, "Data");
        char *inner = data ? json_unescape(data) : NULL;

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
        free(data);
    }

    /* 6. Policy, over the SBOM that was actually signed. */
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
