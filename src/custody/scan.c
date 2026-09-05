#include "custody/scan.h"
#include "convert/build.h"
#include "core/cleanup.h"
#include "core/json.h"
#include "core/run.h"
#include "core/util.h"
#include "custody/vuln.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct scan_opts
{
    const char *artifact;
    const char *outdir;  /* holds metadata/build.json */
    const char *results; /* where the SBOMs land */
    const char *syft;
    const char *grype;
    const char *source; /* overrides the reference build.json recorded */
    bool skip_source;
    bool skip_cve;
    bool no_verify;

    char *meta; /* metadata/build.json, read once */
};

static void scan_usage(void)
{
    fputs(
        "usage: c2vm scan <artifact> [options]\n"
        "\n"
        "  --out <dir>        directory holding metadata/build.json (default: build)\n"
        "  --results <dir>    where the SBOMs are written (default: results)\n"
        "  --syft <path>      syft binary (default: found on PATH)\n"
        "  --grype <path>     grype binary (default: found on PATH)\n"
        "  --source <ref>     source image to scan (default: the digest in build.json)\n"
        "  --skip-source      scan only the disk\n"
        "  --skip-cve         write SBOMs but do not scan for vulnerabilities\n"
        "  --no-verify        do not check the artifact against build.json's hash\n",
        stderr);
}


static void grype_scan(const struct scan_opts *s, const char *grype, const char *name)
{
    step("grype %s", name);

    char *argv[8];
    size_t n = 0;

    argv[n++] = (char *)grype;
    argv[n++] = (char *)P("sbom:%s/sbom-%s.spdx.json", s->results, name);
    argv[n++] = "-o";
    argv[n++] = (char *)P("json=%s/cve-%s.json", s->results, name);
    argv[n] = NULL;

    run_argv_ok(argv);
}

// Turns ubuntu:24.04 into ubuntu, so the digest can be appended
static const char *repo_of(const char *image)
{
    static char buf[512];
    snprintf(buf, sizeof buf, "%s", image);

    char *slash = strrchr(buf, '/');
    char *colon = strrchr(slash ? slash : buf, ':');
    if (colon)
        *colon = '\0';

    char *at = strrchr(buf, '@');
    if (at)
        *at = '\0';

    return buf;
}

// Builds: syft <target> --source-name <name> --source-version <hash>
//  -o spdx-json=results/sbom-<name>.spdx.json
//  -o cyclonedx-json=results/sbom-<name>.cdx.json
static void syft_scan(const struct scan_opts *s, const char *syft, const char *target, const char *name, const char *version)
{
    step("syft %s", target);

    char *argv[16];
    size_t n = 0;

    argv[n++] = (char *)syft;
    argv[n++] = (char *)target;
    argv[n++] = "--source-name";
    argv[n++] = (char *)name;
    argv[n++] = "--source-version";
    argv[n++] = (char *)version;
    argv[n++] = "-o";
    argv[n++] = (char *)P("spdx-json=%s/sbom-%s.spdx.json", s->results, name);
    argv[n++] = "-o";
    argv[n++] = (char *)P("cyclonedx-json=%s/sbom-%s.cdx.json", s->results, name);
    argv[n] = NULL;

    run_argv_ok(argv);
}

/* Returns the recorded sha256 for this artifact. Caller frees. */
static char *verify_artifact(const struct scan_opts *s)
{
    const char *name = basename_of(s->artifact);

    char *want = json_get_in(s->meta, name, "sha256");
    if (!want)
    {
        die("%s/metadata/build.json records no artifact called '%s'; "
            "rebuild with a version of c2vm that writes artifacts[]",
            s->outdir, name);
    }

    if (s->no_verify)
        return want;

    step("verifying %s against build.json", name);

    char *sum = run_capture("sha256sum", s->artifact, NULL);
    char *sp = strchr(sum, ' ');
    if (sp)
        *sp = '\0';

    if (strcmp(sum, want) != 0)
    {
        die("%s does not match build.json\n"
            "  recorded: %s\n"
            "  actual:   %s\n"
            "The disk changed after it was built; rebuild before scanning.",
            s->artifact, want, sum);
    }

    fprintf(stderr, "  sha256 ok: %s\n", want);
    free(sum);

    return want;
}

static void write_tooling(const struct scan_opts *s, const char *syft,
                          const char *syft_ver, const char *syft_schema,
                          const char *grype_ver, const char *db_built,
                          const char *db_schema,
                          const char *image, const char *digest,
                          const char *artifact_sha)
{
    step("recording scan metadata");

    char stamp[32];
    time_t now = time(NULL);
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    write_file(P("%s/tooling.json", s->results),
               "{\n"
               "  \"scanned_at\": \"%s\",\n"
               "  \"c2vm_version\": \"%s\",\n"
               "  \"syft\": {\n"
               "    \"path\": \"%s\",\n"
               "    \"version\": \"%s\",\n"
               "    \"spdx_schema\": \"%s\"\n"
               "  },\n"
               "  \"grype\": {\n"
               "    \"version\": \"%s\",\n"
               "    \"db_schema\": \"%s\",\n"
               "    \"db_built\": \"%s\"\n"
               "  },\n"
               "  \"artifact\": {\n"
               "    \"name\": \"%s\",\n"
               "    \"sha256\": \"%s\",\n"
               "    \"verified\": %s\n"
               "  },\n"
               "  \"source\": {\n"
               "    \"image\": \"%s\",\n"
               "    \"digest\": \"%s\"\n"
               "  }\n"
               "}\n",
               J(stamp), J(C2VM_VERSION),
               J(syft), J(syft_ver), J(syft_schema),
               J(grype_ver ? grype_ver : ""), J(db_schema ? db_schema : ""),
               J(db_built ? db_built : ""),
               J(basename_of(s->artifact)), J(artifact_sha),
               s->no_verify ? "false" : "true",
               J(image), J(digest));
}

static int parse_opts(int argc, char *argv[], struct scan_opts *s)
{
    s->artifact = NULL;
    s->outdir = "build";
    s->results = "results";
    s->syft = NULL;
    s->grype = NULL;
    s->source = NULL;
    s->skip_source = false;
    s->skip_cve = false;
    s->no_verify = false;
    s->meta = NULL;

    for (int i = 0; i < argc; i++)
    {
        const char *a = argv[i];

        if (!strcmp(a, "-h") || !strcmp(a, "--help"))
        {
            scan_usage();
            exit(EXIT_SUCCESS);
        }
        if (!strcmp(a, "--skip-source"))
        {
            s->skip_source = true;
            continue;
        }
        if (!strcmp(a, "--skip-cve"))
        {
            s->skip_cve = true;
            continue;
        }
        if (!strcmp(a, "--no-verify"))
        {
            s->no_verify = true;
            continue;
        }

        if (a[0] == '-')
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "c2vm scan: %s needs a value\n", a);
                return EXIT_USAGE;
            }
            const char *v = argv[++i];

            if (!strcmp(a, "--out"))
                s->outdir = v;
            else if (!strcmp(a, "--results"))
                s->results = v;
            else if (!strcmp(a, "--syft"))
                s->syft = v;
            else if (!strcmp(a, "--grype"))
                s->grype = v;
            else if (!strcmp(a, "--source"))
                s->source = v;
            else
            {
                fprintf(stderr, "c2vm scan: unknown option '%s'\n", a);
                return EXIT_USAGE;
            }
            continue;
        }

        if (s->artifact)
        {
            fprintf(stderr, "c2vm scan: unexpected argument '%s'\n", a);
            return EXIT_USAGE;
        }
        s->artifact = a;
    }

    if (!s->artifact)
    {
        fprintf(stderr, "c2vm scan: no artifact given\n");
        scan_usage();
        return EXIT_USAGE;
    }

    if (access(s->artifact, R_OK) != 0)
    {
        fprintf(stderr, "c2vm scan: cannot read %s: %s\n",
                s->artifact, strerror(errno));
        return EXIT_USAGE;
    }

    const char *dot = strrchr(basename_of(s->artifact), '.');
    if (dot && !strcmp(dot, ".ova"))
    {
        fprintf(stderr,
                "c2vm scan: cannot scan an OVA directly; scan the qcow2 the\n"
                "           same build produced, or extract disk.vmdk first\n");
        return EXIT_USAGE;
    }

    return 0;
}

int cmd_scan(int argc, char *argv[])
{
    struct scan_opts opts;
    int rc = parse_opts(argc, argv, &opts);
    if (rc != 0)
        return rc;

    if (geteuid() != 0)
        die("scan must run as root (guestmount)");

    cleanup_init();

    const char *syft = tool_path("syft", opts.syft);
    const char *grype = opts.skip_cve
                            ? NULL
                            : tool_path("grype", opts.grype);

    opts.meta = read_file(P("%s/metadata/build.json", opts.outdir), 65536);

    char *image = json_get_in(opts.meta, "source", "image");
    char *digest = json_get_in(opts.meta, "source", "digest");
    if (!image || !digest)
        die("%s/metadata/build.json records no source image", opts.outdir);

    char *artifact_sha = verify_artifact(&opts);

    run_ok("mkdir", "-p", opts.results, NULL);

    char *ver_json = run_capture(syft, "version", "-o", "json", NULL);
    char *syft_ver = json_get(ver_json, "version");
    char *syft_schema = json_get(ver_json, "schemaVersion");
    if (!syft_ver)
        die("cannot read a version out of `%s version -o json`", syft);
    fprintf(stderr, "  syft:     %s (spdx schema %s)\n", syft_ver, syft_schema ? syft_schema : "?");

    /*
     * `grype db status` rather than the report's own descriptor: the
     * descriptor sits at the end of a file that runs to tens of megabytes,
     * and this returns the same two fields in a few hundred bytes.
     */
    char *db_json = NULL, *grype_ver = NULL, *db_built = NULL, *db_schema = NULL;
    if (grype)
    {
        grype_env();

        char *gv = run_capture(grype, "version", "-o", "json", NULL);
        grype_ver = json_get(gv, "version");
        free(gv);

        /* Exits non-zero when the database is missing, but still prints the
           JSON saying so - so take the status rather than dying on it. */
        char *dbargv[] = {(char *)grype, "db", "status", "-o", "json", NULL};
        run_argv_capture(dbargv, &db_json);
        db_built = json_get(db_json, "built");
        db_schema = json_get(db_json, "schemaVersion");

        if (!db_built || !*db_built)
            die("grype has no vulnerability database.\n"
                "Run `grype db update` as your own user, not under sudo, "
                "then scan again.");

        fprintf(stderr, "  grype:    %s (db %s, built %s)\n",
                grype_ver ? grype_ver : "?",
                db_schema ? db_schema : "?",
                db_built ? db_built : "?");
    }

    if (!opts.skip_source)
    {
        const char *ref = opts.source ? opts.source : P("registry:%s@%s", repo_of(image), digest);
        syft_scan(&opts, syft, ref, "source", digest);
        if (grype)
            grype_scan(&opts, grype, "source");
    }

    char mnt[PATH_MAX];
    snprintf(mnt, sizeof mnt, "%s/scanmnt", opts.outdir);
    run_ok("mkdir", "-p", mnt, NULL);

    step("mounting %s read-only", opts.artifact);
    run_ok("guestmount", "-a", opts.artifact, "-i", "--ro", mnt, NULL);
    cleanup_push_guestunmount(mnt);

    syft_scan(&opts, syft, P("dir:%s", mnt), "disk", artifact_sha);

    /* Unmount before writing metadata, so a failure to release the disk is reported as an error */
    cleanup_run();

    if (grype)
        grype_scan(&opts, grype, "disk");

    write_tooling(&opts, syft, syft_ver, syft_schema ? syft_schema : "",
                  grype_ver, db_built, db_schema,
                  image, digest, artifact_sha);

    step("done");
    if (!opts.skip_source)
    {
        fprintf(stderr, "  %s/sbom-source.spdx.json\n", opts.results);
        fprintf(stderr, "  %s/sbom-source.cdx.json\n", opts.results);
    }
    fprintf(stderr, "  %s/sbom-disk.spdx.json\n", opts.results);
    fprintf(stderr, "  %s/sbom-disk.cdx.json\n", opts.results);
    if (grype)
    {
        if (!opts.skip_source)
            fprintf(stderr, "  %s/cve-source.json\n", opts.results);
        fprintf(stderr, "  %s/cve-disk.json\n", opts.results);
    }
    fprintf(stderr, "  %s/tooling.json\n", opts.results);

    free(image);
    free(digest);
    free(artifact_sha);
    free(ver_json);
    free(syft_ver);
    free(syft_schema);
    free(db_json);
    free(grype_ver);
    free(db_built);
    free(db_schema);
    free(opts.meta);

    return EXIT_SUCCESS;
}
