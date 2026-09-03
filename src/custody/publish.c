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

#define EXIT_USAGE 2

/* Three commands over one artifact, so they share their options. */
struct pub_opts
{
    const char *artifact; /* push only */
    const char *ref;
    const char *outdir;  /* holds metadata/build.json */
    const char *results; /* holds the SBOM and the diff */
    const char *tool;    /* --oras or --cosign override */
};

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/*
 * Everything downstream signs a digest, never a tag: a tag can be repointed
 * at different content the moment after it is signed, and the signature
 * would still verify against the new thing.
 */
static char *oci_digest(const char *oras, const char *ref)
{
    char *argv[] = {(char *)oras, "manifest", "fetch", "--descriptor", (char *)ref, NULL};

    char *out = NULL;
    if (run_argv_capture(argv, &out) != 0)
        die("cannot resolve %s; is it pushed, and are you logged in?", ref);

    char *digest = json_get(out, "digest");
    free(out);

    if (!digest || strncmp(digest, "sha256:", 7) != 0)
        die("%s did not resolve to a digest", ref);

    return digest;
}

/*
 * The in-toto statement this project exists to produce. Its subject is the
 * disk's hash and its predicate is every decision the build made, so a
 * verifier holding only the artifact can establish what it is and where it
 * came from. Fields come from build.json, which is why that file is written
 * last, after the artifacts it now names.
 */
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
    if (!sha)
        die("%s/metadata/build.json records no artifact called '%s'", o->outdir, name);

    /*
     * Embedded verbatim rather than re-derived: the list the predicate
     * claims must be the same list c2vm diff published, byte for byte, or
     * the attestation and the results contradict each other.
     */
    char *diff = json_slurp(P("%s/sbom-diff.json", o->results));
    char *added = json_array(diff, "added");
    if (!added)
        die("%s/sbom-diff.json has no \"added\" array; run c2vm diff first", o->results);

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

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

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));

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
            {
                fprintf(stderr, "c2vm: %s needs a value\n", a);
                return EXIT_USAGE;
            }
            const char *v = argv[++i];

            if (!strcmp(a, "--out"))
                o->outdir = v;
            else if (!strcmp(a, "--results"))
                o->results = v;
            else if (!strcmp(a, "--oras") || !strcmp(a, "--cosign"))
                o->tool = v;
            else
            {
                fprintf(stderr, "c2vm: unknown option '%s'\n", a);
                return EXIT_USAGE;
            }
            continue;
        }

        if (seen == 0 && positionals == 2)
            o->artifact = a;
        else if (!o->ref)
            o->ref = a;
        else
        {
            fprintf(stderr, "c2vm: unexpected argument '%s'\n", a);
            return EXIT_USAGE;
        }
        seen++;
    }

    if (!o->ref || (positionals == 2 && !o->artifact))
        return EXIT_USAGE;

    return 0;
}

/* ------------------------------------------------------------------ push */

int cmd_push(int argc, char *argv[])
{
    struct pub_opts o;
    if (parse_opts(argc, argv, &o, 2) != 0)
    {
        fputs("usage: c2vm push <artifact> <oci-ref> [--out dir] [--oras path]\n", stderr);
        return EXIT_USAGE;
    }

    char orasbuf[PATH_MAX];
    const char *oras = tool_path("oras", o.tool, orasbuf, sizeof orasbuf);

    char *meta = json_slurp(P("%s/metadata/build.json", o.outdir));
    char *src = json_get_in(meta, "source", "digest");

    char *built = json_get(meta, "built_at");

    step("pushing %s to %s", o.artifact, o.ref);

    /*
     * A disk is not a container image, so it goes up as an OCI artifact with
     * its own media types. Nothing will ever try to run it; the registry is
     * being used as content-addressed storage that cosign can sign.
     */
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

    char buf[PATH_MAX];
    const char *cosign = tool_path("cosign", o.tool, buf, sizeof buf);

    char orasbuf[PATH_MAX];
    const char *oras = tool_path("oras", NULL, orasbuf, sizeof orasbuf);

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
        fputs("usage: c2vm attest <oci-ref> [--out dir] [--results dir]"
              " [--cosign path]\n",
              stderr);
        return EXIT_USAGE;
    }

    char buf[PATH_MAX];
    const char *cosign = tool_path("cosign", o.tool, buf, sizeof buf);

    char orasbuf[PATH_MAX];
    const char *oras = tool_path("oras", NULL, orasbuf, sizeof orasbuf);

    /* The predicate names disk.qcow2 unless told otherwise; push decides
       what was actually published. */
    o.artifact = "disk.qcow2";

    /* Real storage: predicate_write() makes a dozen json_get_in() calls and
       each one burns a P() slot, so a pool pointer would not survive it. */
    char pred[PATH_MAX];
    snprintf(pred, sizeof pred, "%s/predicate.json", o.results);
    predicate_write(&o, pred);

    char *digest = oci_digest(oras, o.ref);
    const char *subject = P("%s@%s", o.ref, digest);

    /* Two claims about one artifact: what is inside it, and how it got made.
       The SBOM has a standard predicate type; the conversion record does not
       exist as a standard, which is the gap this project fills. */
    step("attesting the SBOM");
    run_ok(cosign, "attest", "--yes", "--type", "spdxjson",
           "--predicate", P("%s/sbom-disk.spdx.json", o.results),
           subject, NULL);

    step("attesting the conversion record");
    run_ok(cosign, "attest", "--yes", "--type", "custom", "--predicate", pred, subject, NULL);

    fprintf(stderr, "\n  both attestations attached to %s\n", subject);
    fprintf(stderr, "  entries are public in Rekor; list them with:\n"
                    "    cosign tree %s\n",
            subject);

    free(digest);
    return EXIT_SUCCESS;
}
