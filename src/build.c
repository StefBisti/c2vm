#include "build.h"
#include "cleanup.h"
#include "run.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXIT_USAGE 2

struct build_opts {
    const char *image;
    const char *format;
    const char *size;
    const char *hostname;
    const char *packages;
    const char *kernel;
    const char *fstype;
    const char *ssh_key;
    const char *outdir;
};

static void build_usage(void)
{
    fputs(
        "usage: c2vm build <image-ref> [options]\n"
        "\n"
        "  --format <list>     output formats, comma-separated (default: qcow2)\n"
        "  --size <size>       disk size (default: 10G)\n"
        "  --hostname <name>   guest hostname (default: c2vm)\n"
        "  --packages <list>   extra packages, comma-separated\n"
        "  --kernel <pkg>      kernel package (default: linux-image-virtual)\n"
        "  --fstype <fs>       root filesystem (default: ext4)\n"
        "  --ssh-key <path>    authorized key for the default user\n"
        "  --out <dir>         output directory (default: build)\n"
        "  --dry-run           print every command instead of running it\n",
        stderr);
}

/* Returns 0 on success, EXIT_USAGE on a bad argument list. */
static int parse_opts(int argc, char *argv[], struct build_opts *o)
{
    o->image    = NULL;
    o->format   = "qcow2";
    o->size     = "10G";
    o->hostname = "c2vm";
    o->packages = NULL;
    o->kernel   = "linux-image-virtual";
    o->fstype   = "ext4";
    o->ssh_key  = NULL;
    o->outdir   = "build";

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "--dry-run")) {
            dry_run = true;
            continue;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            build_usage();
            exit(EXIT_SUCCESS);
        }

        if (a[0] == '-') {
            const char **slot = NULL;
            if      (!strcmp(a, "--format"))   slot = &o->format;
            else if (!strcmp(a, "--size"))     slot = &o->size;
            else if (!strcmp(a, "--hostname")) slot = &o->hostname;
            else if (!strcmp(a, "--packages")) slot = &o->packages;
            else if (!strcmp(a, "--kernel"))   slot = &o->kernel;
            else if (!strcmp(a, "--fstype"))   slot = &o->fstype;
            else if (!strcmp(a, "--ssh-key"))  slot = &o->ssh_key;
            else if (!strcmp(a, "--out"))      slot = &o->outdir;
            else {
                fprintf(stderr, "c2vm build: unknown option '%s'\n", a);
                return EXIT_USAGE;
            }

            if (i + 1 >= argc) {
                fprintf(stderr, "c2vm build: %s needs a value\n", a);
                return EXIT_USAGE;
            }
            *slot = argv[++i];
            continue;
        }

        if (o->image) {
            fprintf(stderr, "c2vm build: unexpected argument '%s'\n", a);
            return EXIT_USAGE;
        }
        o->image = a;
    }

    if (!o->image) {
        fprintf(stderr, "c2vm build: no image reference given\n");
        build_usage();
        return EXIT_USAGE;
    }
    return 0;
}

int cmd_build(int argc, char *argv[])
{
    struct build_opts o;
    int rc = parse_opts(argc, argv, &o);
    if (rc != 0)
        return rc;

    /* Every step past this point needs losetup, mount and chroot. */
    if (!dry_run && geteuid() != 0)
        die("build must run as root (try: sudo ./c2vm build ...)");

    cleanup_init();

    step("build plan");
    fprintf(stderr, "  image:    %s\n", o.image);
    fprintf(stderr, "  formats:  %s\n", o.format);
    fprintf(stderr, "  size:     %s\n", o.size);
    fprintf(stderr, "  hostname: %s\n", o.hostname);
    fprintf(stderr, "  kernel:   %s\n", o.kernel);
    fprintf(stderr, "  fstype:   %s\n", o.fstype);
    fprintf(stderr, "  packages: %s\n", o.packages ? o.packages : "(none)");
    fprintf(stderr, "  ssh-key:  %s\n", o.ssh_key ? o.ssh_key : "(none)");
    fprintf(stderr, "  out:      %s\n", o.outdir);

    die("disk build not implemented yet (chunk 2)");
    return EXIT_FAILURE;
}
