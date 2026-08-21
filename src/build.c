#include "build.h"
#include "cleanup.h"
#include "run.h"

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define EXIT_USAGE 2
#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

/* Everything the conversion adds that a container image does not have. */
static const char *BASE_PACKAGES[] = {
    "initramfs-tools",
    "grub-efi-amd64",
    "systemd",
    "systemd-sysv",
    "init",
    "udev",
    "dbus",
    "netplan.io",
    "iproute2",
    "ca-certificates",
    "openssh-server",
    "sudo",
};

/* Phase 0: without these in the initramfs the guest cannot find its root disk. */
static const char *VIRTIO_MODULES =
    "virtio_blk\n"
    "virtio_pci\n"
    "virtio_net\n"
    "virtio_scsi\n";

struct build_opts
{
    const char *image;
    const char *format;
    const char *size;
    const char *hostname;
    const char *packages;
    const char *kernel;
    const char *fstype;
    const char *ssh_key;
    const char *outdir;
    char mnt[PATH_MAX];
};

/*
 * Build a path string. Returns a pointer into a small rotating pool so that
 * several calls can appear in one expression. Valid only until eight further
 * calls have been made - no buffer to manage
 * ex: P("%s/disk.raw", o->outdir) -> "build/disk.raw"
 */

// useful because it requires no buffer for formatting
static const char *P(const char *fmt, ...)
{
    static char pool[8][PATH_MAX];
    static size_t next;

    char *buf = pool[next];
    next = (next + 1) % NELEMS(pool);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, PATH_MAX, fmt, ap);
    va_end(ap);

    return buf;
}

// ex: has_format(o, "qcow2") -> true (o->format = "qcow2,ova")
static bool has_format(const struct build_opts *o, const char *want)
{
    const char *p = o->format;
    size_t n = strlen(want);

    while ((p = strstr(p, want)) != NULL)
    {
        bool left = (p == o->format) || p[-1] == ',';
        bool right = (p[n] == '\0') || p[n] == ',';
        if (left && right)
            return true;
        p += n;
    }
    return false;
}

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
        "  --ssh-key <path>    authorized key for root\n"
        "  --out <dir>         output directory (default: build)\n"
        "  --dry-run           print every command instead of running it\n",
        stderr);
}

/* Returns 0 on success, EXIT_USAGE on a bad argument list. */
static int parse_opts(int argc, char *argv[], struct build_opts *o)
{
    o->image = NULL;
    o->format = "qcow2";
    o->size = "10G";
    o->hostname = "c2vm";
    o->packages = NULL;
    o->kernel = "linux-image-virtual";
    o->fstype = "ext4";
    o->ssh_key = NULL;
    o->outdir = "build";

    for (int i = 0; i < argc; i++)
    {
        const char *a = argv[i];

        if (!strcmp(a, "--dry-run"))
        {
            dry_run = true;
            continue;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help"))
        {
            build_usage();
            exit(EXIT_SUCCESS);
        }

        if (a[0] == '-')
        {
            const char **whereToWriteTheValue = NULL;
            if (!strcmp(a, "--format"))
                whereToWriteTheValue = &o->format;
            else if (!strcmp(a, "--size"))
                whereToWriteTheValue = &o->size;
            else if (!strcmp(a, "--hostname"))
                whereToWriteTheValue = &o->hostname;
            else if (!strcmp(a, "--packages"))
                whereToWriteTheValue = &o->packages;
            else if (!strcmp(a, "--kernel"))
                whereToWriteTheValue = &o->kernel;
            else if (!strcmp(a, "--fstype"))
                whereToWriteTheValue = &o->fstype;
            else if (!strcmp(a, "--ssh-key"))
                whereToWriteTheValue = &o->ssh_key;
            else if (!strcmp(a, "--out"))
                whereToWriteTheValue = &o->outdir;
            else
            {
                fprintf(stderr, "c2vm build: unknown option '%s'\n", a);
                return EXIT_USAGE;
            }

            if (i + 1 >= argc)
            {
                fprintf(stderr, "c2vm build: %s needs a value\n", a);
                return EXIT_USAGE;
            }
            *whereToWriteTheValue = argv[++i];
            continue;
        }

        if (o->image)
        {
            fprintf(stderr, "c2vm build: unexpected argument '%s'\n", a);
            return EXIT_USAGE;
        }
        o->image = a;
    }

    if (!o->image)
    {
        fprintf(stderr, "c2vm build: no image reference given\n");
        build_usage();
        return EXIT_USAGE;
    }

    if (!has_format(o, "qcow2") && !has_format(o, "raw"))
    {
        fprintf(stderr, "c2vm build: --format must include qcow2 or raw\n");
        return EXIT_USAGE;
    }
    return 0;
}

/* ---------------------------------------------------------------- stages */

/*
 * Idempotency: every run starts from an empty output directory, so a second
 * run on a dirty machine rebuilds rather than failing on leftovers.
 */

// deletes then recreates o->outdir
static void prepare_outdir(const struct build_opts *o)
{
    step("preparing %s", o->outdir);
    run("umount", "-R", P("%s/mnt", o->outdir), NULL); /* may fail; fine */
    run_ok("rm", "-rf", o->outdir, NULL);
    run_ok("mkdir", "-p", P("%s/metadata", o->outdir), NULL);
    run_ok("mkdir", "-p", P("%s/mnt", o->outdir), NULL);
}

// populates build/rootfs from the image
static void extract_rootfs(const struct build_opts *o)
{
    step("extracting %s", o->image);
    run_ok("src/extract-rootfs.sh", o->image, P("%s/rootfs", o->outdir), NULL);
}

// creates and partitions the raw disk file. No loop device involved yet
static void create_disk(const struct build_opts *o)
{
    char disk[PATH_MAX];
    snprintf(disk, sizeof disk, "%s/disk.raw", o->outdir);

    step("creating %s (%s)", disk, o->size);
    run_ok("qemu-img", "create", "-f", "raw", disk, o->size, NULL);

    /* GPT: a 512 MiB ESP for the firmware, the rest for the root filesystem. */
    run_ok("parted", "-s", disk, "mklabel", "gpt", NULL);
    run_ok("parted", "-s", disk, "mkpart", "ESP", "fat32", "1MiB", "513MiB", NULL);
    run_ok("parted", "-s", disk, "set", "1", "esp", "on", NULL);
    run_ok("parted", "-s", disk, "mkpart", "root", o->fstype, "513MiB", "100%", NULL);
}

/* Returns the loop device, e.g. "/dev/loop12". Caller frees. */
static char *attach_and_format(const struct build_opts *o)
{
    step("attaching and formatting");

    /* --partscan is what creates the pN nodes */
    char *loop = run_capture("losetup", "--find", "--show", "--partscan",
                             P("%s/disk.raw", o->outdir), NULL);
    cleanup_push_losetup(loop);

    run_ok("mkfs.vfat", "-F32", "-n", "ESP", P("%sp1", loop), NULL);
    run_ok(P("mkfs.%s", o->fstype), "-L", "cloudimg-rootfs", P("%sp2", loop), NULL);

    return loop;
}

static void mount_all(const struct build_opts *o, const char *loop)
{
    step("mounting on %s", o->mnt);
    run_ok("mount", P("%sp2", loop), o->mnt, NULL);
    cleanup_push_umount(o->mnt);

    run_ok("rsync", "-aHAX", "--numeric-ids",
           P("%s/rootfs/", o->outdir), P("%s/", o->mnt), NULL);

    run_ok("mkdir", "-p", P("%s/boot/efi", o->mnt), NULL);
    run_ok("mount", P("%sp1", loop), P("%s/boot/efi", o->mnt), NULL);
    cleanup_push_umount(P("%s/boot/efi", o->mnt));

    /*
     * The five interfaces dpkg and grub need inside the chroot. Each is
     * registered separately so cleanup unmounts them in reverse order, and
     * made rslave so unmounting cannot propagate back to the host's /dev.
     */
    static const char *BINDS[] = {"dev", "dev/pts", "proc", "sys", "run"};
    for (size_t i = 0; i < NELEMS(BINDS); i++)
    {
        const char *target = P("%s/%s", o->mnt, BINDS[i]);
        run_ok("mount", "--bind", P("/%s", BINDS[i]), target, NULL);
        run_ok("mount", "--make-rslave", target, NULL);
        cleanup_push_umount(target);
    }

    /* dns */
    run_ok("cp", "/etc/resolv.conf", P("%s/etc/resolv.conf", o->mnt), NULL);
}

static void write_guest_config(const struct build_opts *o, const char *loop)
{
    step("writing guest configuration");

    /* Postinst scripts must not try to start services with no PID 1 here. */
    write_file(P("%s/usr/sbin/policy-rc.d", o->mnt), "#!/bin/sh\nexit 101\n");
    run_ok("chmod", "0755", P("%s/usr/sbin/policy-rc.d", o->mnt), NULL);

    char *root_uuid = run_capture("blkid", "-s", "UUID", "-o", "value",
                                  P("%sp2", loop), NULL);
    char *esp_uuid = run_capture("blkid", "-s", "UUID", "-o", "value",
                                 P("%sp1", loop), NULL);

    /* By UUID, never by /dev/sdaN — the guest enumerates disks differently. */
    write_file(P("%s/etc/fstab", o->mnt),
               "# <device> <mount> <fs> <options> <dump> <pass>\n"
               "UUID=%s / %s defaults 0 1\n"
               "UUID=%s /boot/efi vfat umask=0077 0 1\n",
               root_uuid, o->fstype, esp_uuid);

    write_file(P("%s/etc/hostname", o->mnt), "%s\n", o->hostname);
    write_file(P("%s/etc/hosts", o->mnt),
               "127.0.0.1\tlocalhost\n"
               "127.0.1.1\t%s\n",
               o->hostname);

    free(root_uuid);
    free(esp_uuid);
}

// equivalent to:
//
/* chroot build/mnt env DEBIAN_FRONTEND=noninteractive apt-get install -y \
   --no-install-recommends linux-image-virtual initramfs-tools grub-efi-amd64 \
   systemd systemd-sysv init udev dbus netplan.io iproute2 ca-certificates \
   openssh-server sudo <anything from --packages> */
static void apt_install(const struct build_opts *o)
{
    char *argv[128];
    size_t n = 0;

    argv[n++] = "chroot";
    argv[n++] = (char *)o->mnt;
    argv[n++] = "env";
    argv[n++] = "DEBIAN_FRONTEND=noninteractive";
    argv[n++] = "apt-get";
    argv[n++] = "install";
    argv[n++] = "-y";
    argv[n++] = "--no-install-recommends";
    argv[n++] = (char *)o->kernel;

    for (size_t i = 0; i < NELEMS(BASE_PACKAGES); i++)
        argv[n++] = (char *)BASE_PACKAGES[i];

    char *extra = o->packages ? strdup(o->packages) : NULL;
    if (extra)
        for (char *t = strtok(extra, ","); t != NULL; t = strtok(NULL, ","))
            if (n < NELEMS(argv) - 1)
                argv[n++] = t;

    argv[n] = NULL;
    run_argv_ok(argv);
    free(extra);
}

// writes build/metadata/packages-before.txt and build/metadata/packages-after.txt
// build/mnt gets a kernel, GRUB installed, serial console enabled, SSH key placed
static void install_system(const struct build_opts *o)
{
    step("installing kernel, bootloader and init");

    run_ok("chroot", o->mnt, "env", "DEBIAN_FRONTEND=noninteractive",
           "apt-get", "update", NULL);

    /* Snapshot before, so the conversion delta is attributable per package. */
    char *before = run_capture("chroot", o->mnt, "dpkg-query", "-W",
                               "-f=${Package}\t${Version}\n", NULL);
    write_file(P("%s/metadata/packages-before.txt", o->outdir), "%s\n", before);
    free(before);

    apt_install(o);

    /*
     * Both files below are conffiles of packages installed just above, so
     * they are written after the install rather than before it — the
     * directories do not exist in a container rootfs.
     */
    write_file(P("%s/etc/initramfs-tools/modules", o->mnt), "%s", VIRTIO_MODULES);
    run_ok("chroot", o->mnt, "update-initramfs", "-u", "-k", "all", NULL);

    /* Serial console on GRUB and on the kernel cmdline; the last one wins. */
    write_file(P("%s/etc/default/grub", o->mnt),
               "GRUB_TIMEOUT=5\n"
               "GRUB_TERMINAL=\"console serial\"\n"
               "GRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200\"\n"
               "GRUB_CMDLINE_LINUX_DEFAULT=\"\"\n"
               "GRUB_CMDLINE_LINUX=\"console=tty0 console=ttyS0,115200n8\"\n");

    /* --removable writes the UEFI fallback path; --no-nvram avoids the host. */
    run_ok("chroot", o->mnt, "grub-install", "--removable", "--no-nvram",
           "--target=x86_64-efi", "--efi-directory=/boot/efi",
           "--boot-directory=/boot", NULL);
    run_ok("chroot", o->mnt, "update-grub", NULL);

    /* Point the fallback binary's prefix at the real config on the root fs. */
    run_ok("mkdir", "-p", P("%s/boot/efi/boot/grub", o->mnt), NULL);
    write_file(P("%s/boot/efi/boot/grub/grub.cfg", o->mnt),
               "set prefix=($root)/boot/grub\n"
               "configfile $prefix/grub.cfg\n");

    run_ok("chroot", o->mnt, "systemctl", "enable", "serial-getty@ttyS0.service", NULL);

    if (o->ssh_key)
    {
        /* Stage 2.2 replaces this with cloud-init. No password is ever set. */
        run_ok("mkdir", "-p", P("%s/root/.ssh", o->mnt), NULL);
        run_ok("cp", o->ssh_key, P("%s/root/.ssh/authorized_keys", o->mnt), NULL);
        run_ok("chmod", "0600", P("%s/root/.ssh/authorized_keys", o->mnt), NULL);
    }

    char *after = run_capture("chroot", o->mnt, "dpkg-query", "-W",
                              "-f=${Package}\t${Version}\n", NULL);
    write_file(P("%s/metadata/packages-after.txt", o->outdir), "%s\n", after);
    free(after);

    run_ok("chroot", o->mnt, "apt-get", "clean", NULL);
    run_ok("rm", "-f", P("%s/usr/sbin/policy-rc.d", o->mnt), NULL);
    run_ok("rm", "-f", P("%s/etc/resolv.conf", o->mnt), NULL);
}

static void write_metadata(const struct build_opts *o)
{
    step("recording build metadata");

    char *digest = run_capture("skopeo", "inspect", "--format", "{{.Digest}}",
                               P("docker://%s", o->image), NULL);
    char *kver = run_capture("chroot", o->mnt, "dpkg-query", "-W",
                             "-f=${Version}", o->kernel, NULL);
    char *gver = run_capture("chroot", o->mnt, "dpkg-query", "-W",
                             "-f=${Version}", "grub-efi-amd64", NULL);
    char *host = run_capture("uname", "-srm", NULL);

    char stamp[32];
    time_t now = time(NULL);
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    write_file(P("%s/metadata/build.json", o->outdir),
               "{\n"
               "  \"c2vm_version\": \"%s\",\n"
               "  \"built_at\": \"%s\",\n"
               "  \"backend\": \"native\",\n"
               "  \"host_kernel\": \"%s\",\n"
               "  \"source\": {\n"
               "    \"image\": \"%s\",\n"
               "    \"digest\": \"%s\"\n"
               "  },\n"
               "  \"disk\": {\n"
               "    \"size\": \"%s\",\n"
               "    \"fstype\": \"%s\",\n"
               "    \"formats\": \"%s\"\n"
               "  },\n"
               "  \"kernel\": {\n"
               "    \"package\": \"%s\",\n"
               "    \"version\": \"%s\"\n"
               "  },\n"
               "  \"bootloader\": {\n"
               "    \"package\": \"grub-efi-amd64\",\n"
               "    \"version\": \"%s\"\n"
               "  },\n"
               "  \"flags\": {\n"
               "    \"hostname\": \"%s\",\n"
               "    \"extra_packages\": \"%s\",\n"
               "    \"ssh_key\": %s\n"
               "  },\n"
               "  \"packages_before\": \"metadata/packages-before.txt\",\n"
               "  \"packages_after\": \"metadata/packages-after.txt\"\n"
               "}\n",
               C2VM_VERSION, stamp, host,
               o->image, digest,
               o->size, o->fstype, o->format,
               o->kernel, kver,
               gver,
               o->hostname, o->packages ? o->packages : "",
               o->ssh_key ? "true" : "false");

    free(digest);
    free(kver);
    free(gver);
    free(host);
}

static void convert_formats(const struct build_opts *o)
{
    if (!has_format(o, "qcow2"))
        return;

    step("converting to qcow2");
    run_ok("qemu-img", "convert", "-f", "raw", "-O", "qcow2", "-c",
           P("%s/disk.raw", o->outdir), P("%s/disk.qcow2", o->outdir), NULL);
}

/* ----------------------------------------------------------------- entry */

int cmd_build(int argc, char *argv[])
{
    struct build_opts o;
    int rc = parse_opts(argc, argv, &o);
    if (rc != 0)
        return rc;

    /* Every step past this point needs losetup, mount and chroot. */
    if (!dry_run && geteuid() != 0)
        die("build must run as root");

    if (!dry_run)
    {
        if (unshare(CLONE_NEWNS) != 0)
            die("cannot create mount namespace: %s", strerror(errno));
        run_ok("mount", "--make-rprivate", "/", NULL);
    }

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

    snprintf(o.mnt, sizeof o.mnt, "%s/mnt", o.outdir);

    prepare_outdir(&o);
    extract_rootfs(&o);
    create_disk(&o);

    char *loop = attach_and_format(&o);
    mount_all(&o, loop);
    write_guest_config(&o, loop);
    install_system(&o);
    write_metadata(&o);

    /* Unmount and detach before converting, so qcow2 sees a quiesced disk. */
    cleanup_run();
    free(loop);

    convert_formats(&o);

    step("done");
    fprintf(stderr, "  %s/disk.raw\n", o.outdir);
    if (has_format(&o, "qcow2"))
        fprintf(stderr, "  %s/disk.qcow2\n", o.outdir);
    fprintf(stderr, "  %s/metadata/build.json\n", o.outdir);

    return EXIT_SUCCESS;
}
