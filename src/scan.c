#include "scan.h"
#include "build.h"
#include "cleanup.h"
#include "json.h"
#include "run.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define EXIT_USAGE 2
#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

struct scan_opts
{
    const char *artifact;
    const char *outdir;  /* holds metadata/build.json */
    const char *results; /* where the SBOMs land */
    const char *syft;
    const char *source; /* overrides the reference build.json recorded */
    bool skip_source;
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
        "  --source <ref>     source image to scan (default: the digest in build.json)\n"
        "  --skip-source      scan only the disk\n"
        "  --no-verify        do not check the artifact against build.json's hash\n",
        stderr);
}

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/*
 * scan runs as root for guestmount, and root's PATH does not include the
 * ~/.local/bin that syft's installer writes to. Look where sudo came from
 * before giving up, so the common case needs no --syft.
 *
 * The result outlives dozens of further P() calls — json_get() makes one per
 * lookup — so it gets storage of its own rather than a slot in the pool.
 */
static const char *find_syft(const struct scan_opts *s)
{
    static char found[PATH_MAX];

    if (s->syft)
        return s->syft;

    static const char *DIRS[] = {
        "/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"};

    for (size_t i = 0; i < NELEMS(DIRS); i++)
    {
        snprintf(found, sizeof found, "%s/syft", DIRS[i]);
        if (access(found, X_OK) == 0)
            return found;
    }

    const char *user = getenv("SUDO_USER");
    if (user)
    {
        snprintf(found, sizeof found, "/home/%s/.local/bin/syft", user);
        if (access(found, X_OK) == 0)
            return found;
    }

    const char *home = getenv("HOME");
    if (home)
    {
        snprintf(found, sizeof found, "%s/.local/bin/syft", home);
        if (access(found, X_OK) == 0)
            return found;
    }

    die("cannot find syft; install it or pass --syft <path>");
    return NULL; /* unreachable */
}

/*
 * "ubuntu:24.04" -> "ubuntu", so the digest can be appended. The tag is the
 * last colon *after* the last slash: a registry may carry a port, and
 * localhost:5000/img:tag must not lose its port.
 */
static const char *repo_of(const char *image)
{
    static char buf[512];
    snprintf(buf, sizeof buf, "%s", image);

    char *slash = strrchr(buf, '/');
    char *colon = strrchr(slash ? slash : buf, ':');
    if (colon)
        *colon = '\0';

    /* Already digest-pinned: strip that too, the caller re-appends one. */
    char *at = strrchr(buf, '@');
    if (at)
        *at = '\0';

    return buf;
}

/*
 * Both SBOM formats come out of a single syft invocation, so they cannot
 * describe different scans. --source-name/--source-version put the artifact
 * hash inside the document, which is what Phase 3.4 attests to, and they
 * silence syft's warning about an unnamed directory source.
 */
static void syft_scan(const struct scan_opts *s, const char *syft,
                      const char *target, const char *name, const char *version)
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
        die("%s/metadata/build.json records no artifact called '%s'; "
            "rebuild with a version of c2vm that writes artifacts[]",
            s->outdir, name);

    if (s->no_verify)
        return want;

    step("verifying %s against build.json", name);

    char *sum = run_capture("sha256sum", s->artifact, NULL);
    char *sp = strchr(sum, ' ');
    if (sp)
        *sp = '\0';

    if (strcmp(sum, want) != 0)
        die("%s does not match build.json\n"
            "  recorded: %s\n"
            "  actual:   %s\n"
            "The disk changed after it was built; rebuild before scanning.",
            s->artifact, want, sum);

    fprintf(stderr, "  sha256 ok: %s\n", want);
    free(sum);

    return want;
}

static void write_tooling(const struct scan_opts *s, const char *syft,
                          const char *syft_ver, const char *syft_schema,
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
    s->source = NULL;
    s->skip_source = false;
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

    /* guestmount reads disk images, not archives. Say so plainly rather
       than letting libguestfs fail with an appliance error. */
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
    struct scan_opts s;
    int rc = parse_opts(argc, argv, &s);
    if (rc != 0)
        return rc;

    /* guestmount needs root, and so does reading the mount it creates. */
    if (geteuid() != 0)
        die("scan must run as root (guestmount)");

    cleanup_init();

    const char *syft = find_syft(&s);
    s.meta = read_file(P("%s/metadata/build.json", s.outdir), 65536);

    char *image = json_get_in(s.meta, "source", "image");
    char *digest = json_get_in(s.meta, "source", "digest");
    if (!image || !digest)
        die("%s/metadata/build.json records no source image", s.outdir);

    char *artifact_sha = verify_artifact(&s);

    run_ok("mkdir", "-p", s.results, NULL);

    /* Recorded so Stage 3.2 can prove both SBOMs came from one syft. */
    char *ver_json = run_capture(syft, "version", "-o", "json", NULL);
    char *syft_ver = json_get(ver_json, "version");
    char *syft_schema = json_get(ver_json, "schemaVersion");
    if (!syft_ver)
        die("cannot read a version out of `%s version -o json`", syft);
    fprintf(stderr, "  syft:     %s (spdx schema %s)\n",
            syft_ver, syft_schema ? syft_schema : "?");

    /*
     * Pinned by digest, never by tag. `ubuntu:24.04` resolves to a different
     * image next month, and a source SBOM that does not describe the image
     * this disk was actually built from breaks the whole chain.
     */
    if (!s.skip_source)
    {
        const char *ref = s.source
                              ? s.source
                              : P("registry:%s@%s", repo_of(image), digest);
        syft_scan(&s, syft, ref, "source", digest);
    }

    /* guestmount rather than a loop device: it reads qcow2 directly and
       needs no nbd module. The loop path stays available for disk.raw.
       Real storage, not P(): syft_scan() makes further P() calls. */
    char mnt[PATH_MAX];
    snprintf(mnt, sizeof mnt, "%s/scanmnt", s.outdir);
    run_ok("mkdir", "-p", mnt, NULL);

    step("mounting %s read-only", s.artifact);
    run_ok("guestmount", "-a", s.artifact, "-i", "--ro", mnt, NULL);
    cleanup_push_guestunmount(mnt);

    syft_scan(&s, syft, P("dir:%s", mnt), "disk", artifact_sha);

    /* Unmount before writing metadata, so a failure to release the disk is
       reported as an error rather than hidden behind a successful exit. */
    cleanup_run();

    write_tooling(&s, syft, syft_ver, syft_schema ? syft_schema : "",
                  image, digest, artifact_sha);

    step("done");
    if (!s.skip_source)
    {
        fprintf(stderr, "  %s/sbom-source.spdx.json\n", s.results);
        fprintf(stderr, "  %s/sbom-source.cdx.json\n", s.results);
    }
    fprintf(stderr, "  %s/sbom-disk.spdx.json\n", s.results);
    fprintf(stderr, "  %s/sbom-disk.cdx.json\n", s.results);
    fprintf(stderr, "  %s/tooling.json\n", s.results);

    free(image);
    free(digest);
    free(artifact_sha);
    free(ver_json);
    free(syft_ver);
    free(syft_schema);
    free(s.meta);

    return EXIT_SUCCESS;
}
