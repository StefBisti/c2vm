#include "custody/publish.h"
#include "core/json.h"
#include "core/run.h"
#include "core/util.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct pub_opts
{
    const char *artifact; /* push only */
    const char *ref;
    const char *outdir;  /* holds metadata/build.json */
    const char *results; /* holds the SBOM and the diff */
    const char *tool;    /* --oras or --cosign override */
};

char *oci_digest(const char *oras, const char *ref)
{
    // returns something like: {"mediaType":"application/vnd.oci.image.manifest.v1+json",
    // "digest":"sha256:3f14b53626a53abd5cb7e5cb5835de3894641ef870f32aebbafed7b9aee67a8c","size":692}stefan@stef
    char *argv[] = {(char *)oras, "manifest", "fetch", "--descriptor", (char *)ref, NULL};

    char *out = NULL;
    die_if(run_argv_capture(argv, &out) != 0, "cannot resolve %s; is it pushed, and are you logged in?", ref);

    char *digest = json_get(out, "digest");
    free(out);

    die_if(!digest || strncmp(digest, "sha256:", 7) != 0, "%s did not resolve to a digest", ref);

    return digest;
}

// creates the in-toto attestation
static void predicate_write(const struct pub_opts *o, const char *path)
{
    step("building the conversion predicate");

    char *meta = json_slurp(P("%s/metadata/build.json", o->outdir));

    char *image = json_get_in(meta, "source", "image");
    char *digest = json_get_in(meta, "source", "digest");
    char *backend = json_get(meta, "backend");
    char *built_at = json_get(meta, "built_at");
    char *version = json_get(meta, "c2vm_version");
    char *kpkg = json_get_in(meta, "kernel", "package");
    char *kver = json_get_in(meta, "kernel", "version");
    char *bpkg = json_get_in(meta, "bootloader", "package");
    char *bver = json_get_in(meta, "bootloader", "version");
    char *hostname = json_get_in(meta, "flags", "hostname");
    char *user = json_get_in(meta, "flags", "user");
    char *size = json_get_in(meta, "disk", "size");
    char *fstype = json_get_in(meta, "disk", "fstype");

    const char *name = basename_of(o->artifact ? o->artifact : "disk.qcow2");
    char *sha = json_get_in(meta, name, "sha256");
    die_if(!sha, "%s/metadata/build.json records no artifact called '%s'", o->outdir, name);

    char *diff = json_slurp(P("%s/sbom-diff.json", o->results));
    char *added = json_array(diff, "added_deb");
    die_if(!added, "%s/sbom-diff.json has no \"added_deb\" array; re-run c2vm sbom-diff", o->results);

    FILE *f = fopen(path, "w");
    die_if(!f, "cannot write %s: %s", path, strerror(errno));

    fprintf(f,
            "{\n"
            "  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
            "  \"subject\": [\n"
            "    { \"name\": \"%s\", \"digest\": { \"sha256\": \"%s\" } }\n"
            "  ],\n"
            "  \"predicateType\": \"https://c2vm.dev/conversion/v1\",\n"
            "  \"predicate\": {\n"
            "    \"source\": { \"image\": \"%s\", \"digest\": \"%s\" },\n"
            "    \"backend\": \"%s\",\n"
            "    \"kernel\": { \"package\": \"%s\", \"version\": \"%s\" },\n"
            "    \"bootloader\": { \"package\": \"%s\", \"version\": \"%s\" },\n"
            "    \"disk\": { \"size\": \"%s\", \"fstype\": \"%s\" },\n"
            "    \"flags\": { \"hostname\": \"%s\", \"user\": \"%s\" },\n"
            "    \"builder\": { \"c2vm_version\": \"%s\", \"built_at\": \"%s\" },\n"
            "    \"packages_added\": %s\n"
            "  }\n"
            "}\n",
            J(name), J(sha),
            J(image), J(digest),
            J(backend),
            J(kpkg), J(kver),
            J(bpkg), J(bver),
            J(size), J(fstype),
            J(hostname), J(user),
            J(version), J(built_at),
            added);

    die_if(fclose(f) != 0, "cannot close %s: %s", path, strerror(errno));

    fprintf(stderr, "  > %s\n", path);

    free(meta);
    free(diff);
    free(added);
    free(image);
    free(digest);
    free(backend);
    free(built_at);
    free(version);
    free(kpkg);
    free(kver);
    free(bpkg);
    free(bver);
    free(hostname);
    free(user);
    free(size);
    free(fstype);
    free(sha);
}

// used for all 3
static int parse_opts(int argc, char *argv[], struct pub_opts *o, int positionals)
{
    o->artifact = NULL;
    o->ref = NULL;
    o->outdir = "build";
    o->results = "results";
    o->tool = NULL;

    int seen = 0;

    for (int i = 0; i < argc; i++)
    {
        const char *a = argv[i];

        if (!strcmp(a, "-h") || !strcmp(a, "--help"))
            return EXIT_USAGE;

        if (a[0] == '-')
        {
            if (i + 1 >= argc)
                return usage_err("%s needs a value", a);
            const char *v = argv[++i];

            if (!strcmp(a, "--out"))
                o->outdir = v;
            else if (!strcmp(a, "--results"))
                o->results = v;
            else if (!strcmp(a, "--oras") || !strcmp(a, "--cosign"))
                o->tool = v;
            else if (!strcmp(a, "--artifact"))
                o->artifact = v;
            else
                return usage_err("unknown option '%s'", a);
            continue;
        }

        if (seen == 0 && positionals == 2)
            o->artifact = a;
        else if (!o->ref)
            o->ref = a;
        else
            return usage_err("unexpected argument '%s'", a);
        seen++;
    }

    if (!o->ref || (positionals == 2 && !o->artifact))
        return EXIT_USAGE;

    return 0;
}

/* ------------------------------------------------------------------ push */

/* Equivalent to:

    oras push <ref>
    --artifact-type application/vnd.c2vm.disk.v1+json
    --annotation dev.c2vm.source-digest=sha256:…
    --annotation org.opencontainers.image.created=…
    build/disk.qcow2:application/vnd.c2vm.disk.qcow2
*/
int cmd_push(int argc, char *argv[])
{
    struct pub_opts o;
    if (parse_opts(argc, argv, &o, 2) != 0)
    {
        fputs("usage: c2vm push <artifact> <oci-ref> [--out dir] [--oras path]\n", stderr);
        return EXIT_USAGE;
    }

    const char *oras = tool_path("oras", o.tool);

    char *meta = json_slurp(P("%s/metadata/build.json", o.outdir));
    char *src = json_get_in(meta, "source", "digest");

    char *built = json_get(meta, "built_at");

    step("pushing %s to %s", o.artifact, o.ref);

    char *cmd[16];
    size_t n = 0;
    cmd[n++] = (char *)oras;
    cmd[n++] = "push";
    cmd[n++] = (char *)o.ref;
    cmd[n++] = "--artifact-type";
    cmd[n++] = "application/vnd.c2vm.disk.v1+json";
    cmd[n++] = "--annotation";
    cmd[n++] = (char *)P("dev.c2vm.source-digest=%s", src ? src : "unknown");
    cmd[n++] = "--annotation";
    cmd[n++] = (char *)P("org.opencontainers.image.created=%s", built ? built : "");
    cmd[n++] = (char *)P("%s:application/vnd.c2vm.disk.qcow2", o.artifact);
    cmd[n] = NULL;

    run_argv_ok(cmd);

    char *digest = oci_digest(oras, o.ref);
    fprintf(stderr, "\n  %s@%s\n", o.ref, digest);
    fprintf(stderr, "  sign it with: c2vm sign %s\n", o.ref);

    free(digest);
    free(src);
    free(built);
    free(meta);
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ sign */

int cmd_sign(int argc, char *argv[])
{
    struct pub_opts o;
    if (parse_opts(argc, argv, &o, 1) != 0)
    {
        fputs("usage: c2vm sign <oci-ref> [--cosign path]\n", stderr);
        return EXIT_USAGE;
    }

    const char *cosign = tool_path("cosign", o.tool);

    const char *oras = tool_path("oras", NULL);

    char *digest = oci_digest(oras, o.ref);

    step("signing %s@%s", o.ref, digest);
    fputs("  a browser will open: cosign gets a short-lived certificate\n"
          "  from Fulcio tied to the identity you log in with\n",
          stderr);

    run_ok(cosign, "sign", "--yes", P("%s@%s", o.ref, digest), NULL);

    free(digest);
    return EXIT_SUCCESS;
}

/* ---------------------------------------------------------------- attest */

int cmd_attest(int argc, char *argv[])
{
    struct pub_opts o;
    if (parse_opts(argc, argv, &o, 1) != 0)
    {
        fputs("usage: c2vm attest <oci-ref> [--artifact name] [--out dir] [--results dir] [--cosign path]\n", stderr);
        return EXIT_USAGE;
    }

    const char *cosign = tool_path("cosign", o.tool);

    const char *oras = tool_path("oras", NULL);

    if (!o.artifact)
        o.artifact = "disk.qcow2";

    const char *pred = P("%s/predicate.json", o.results);
    predicate_write(&o, pred);

    char *digest = oci_digest(oras, o.ref);
    const char *subject = P("%s@%s", o.ref, digest);

    step("attesting the SBOM");
    run_ok(cosign, "attest", "--yes", "--type", "spdxjson", "--predicate", P("%s/sbom-disk.spdx.json", o.results), subject, NULL);

    step("attesting the conversion record");
    run_ok(cosign, "attest", "--yes", "--type", "custom", "--predicate", pred, subject, NULL);

    fprintf(stderr, "\n  both attestations attached to %s\n", subject);
    fprintf(stderr, "  entries are public in Rekor; list them with:\n    cosign tree %s\n", subject);

    free(digest);
    return EXIT_SUCCESS;
}
