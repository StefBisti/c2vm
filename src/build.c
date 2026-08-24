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
#include <crypt.h>

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
    "cloud-init",
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
    const char *user;
    const char *pw_file;
    bool compress;
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

/*
 * JSON-escape into the same kind of rotating pool as P(). build.json becomes
 * the signed attestation predicate in Phase 3, so a quote or a backslash in
 * an image reference or a package list must not be able to break its syntax.
 * The pool is larger than P()'s because one write_file() call escapes a dozen
 * fields at once.
 */
static const char *J(const char *s)
{
    static char pool[16][PATH_MAX];
    static size_t next;

    char *buf = pool[next];
    next = (next + 1) % NELEMS(pool);

    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++)
    {
        char esc[8];
        const char *rep = esc;

        switch (*p)
        {
        case '"':
            rep = "\\\"";
            break;
        case '\\':
            rep = "\\\\";
            break;
        case '\n':
            rep = "\\n";
            break;
        case '\r':
            rep = "\\r";
            break;
        case '\t':
            rep = "\\t";
            break;
        default:
            if (*p < 0x20)
                snprintf(esc, sizeof esc, "\\u%04x", *p);
            else
            {
                esc[0] = (char)*p;
                esc[1] = '\0';
            }
        }

        size_t n = strlen(rep);
        if (w + n >= PATH_MAX)
            break; /* truncate rather than overflow */
        memcpy(buf + w, rep, n);
        w += n;
    }
    buf[w] = '\0';

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
        "  --format <list>        output formats, comma-separated (default: qcow2)\n"
        "  --size <size>          disk size (default: 10G)\n"
        "  --hostname <name>      guest hostname (default: c2vm)\n"
        "  --packages <list>      extra packages, comma-separated\n"
        "  --kernel <pkg>         kernel package (default: linux-image-virtual)\n"
        "  --fstype <fs>          root filesystem (default: ext4)\n"
        "  --ssh-key <path>       authorized key for root\n"
        "  --out <dir>            output directory (default: build)\n"
        "  --user <name>          default user account (default: c2vm)\n"
        "  --root-password <file> file holding a root password, hashed\n"
        "  --compress             compress the qcow2 (changes its hash)\n"
        "  --dry-run              print every command instead of running it\n",
        stderr);
}

static bool readable(const char *flag, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        fprintf(stderr, "c2vm build: %s: cannot read %s: %s\n",
                flag, path, strerror(errno));
        return false;
    }
    fclose(f);
    return true;
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
    o->user = "c2vm";
    o->pw_file = NULL;
    o->compress = false;

    for (int i = 0; i < argc; i++)
    {
        const char *a = argv[i];

        if (!strcmp(a, "--dry-run"))
        {
            dry_run = true;
            continue;
        }
        if (!strcmp(a, "--compress"))
        {
            o->compress = true;
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
            else if (!strcmp(a, "--user"))
                whereToWriteTheValue = &o->user;
            else if (!strcmp(a, "--root-password"))
                whereToWriteTheValue = &o->pw_file;

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

    if (o->ssh_key && !readable("--ssh-key", o->ssh_key))
        return EXIT_USAGE;
    if (o->pw_file && !readable("--root-password", o->pw_file))
        return EXIT_USAGE;

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
        {
            /* Never install a silently shortened package list. */
            if (n >= NELEMS(argv) - 1)
                die("too many packages (limit is %zu)", NELEMS(argv) - 1);
            argv[n++] = t;
        }

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

    char *after = run_capture("chroot", o->mnt, "dpkg-query", "-W",
                              "-f=${Package}\t${Version}\n", NULL);
    write_file(P("%s/metadata/packages-after.txt", o->outdir), "%s\n", after);
    free(after);

    run_ok("chroot", o->mnt, "apt-get", "clean", NULL);
    run_ok("rm", "-f", P("%s/usr/sbin/policy-rc.d", o->mnt), NULL);
    run_ok("rm", "-f", P("%s/etc/resolv.conf", o->mnt), NULL);
}

static char *read_small_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        die("cannot read %s: %s", path, strerror(errno));

    char buf[8192];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
        buf[--n] = '\0';

    return strdup(buf);
}

static char *hash_password(const char *plain)
{
    static const char ALPHABET[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    unsigned char raw[16];
    FILE *f = fopen("/dev/urandom", "r");
    if (!f || fread(raw, 1, sizeof raw, f) != sizeof raw)
        die("cannot read /dev/urandom");
    fclose(f);

    /* 256 is a multiple of 64, so the modulo below is unbiased. */
    char setting[3 + sizeof raw + 1];
    memcpy(setting, "$6$", 3);
    for (size_t i = 0; i < sizeof raw; i++)
        setting[3 + i] = ALPHABET[raw[i] % (sizeof ALPHABET - 1)];
    setting[3 + sizeof raw] = '\0';

    char *hash = crypt(plain, setting);
    if (!hash || hash[0] == '*') /* libxcrypt's failure signal */
        die("password hashing failed");

    return strdup(hash);
}

static char *read_source_digest(const struct build_opts *o)
{
    if (dry_run)
        return strdup("DRYRUN");

    const char *path = P("%s/metadata/source.json", o->outdir);
    char *json = read_small_file(path);

    /* Small enough not to justify a JSON parser: one known key, one string. */
    char *key = strstr(json, "\"source_digest\"");
    char *val = key ? strchr(key + strlen("\"source_digest\""), '"') : NULL;
    char *end = val ? strchr(val + 1, '"') : NULL;
    if (!end)
        die("%s does not contain a source_digest", path);

    *end = '\0';
    char *digest = strdup(val + 1);
    free(json);
    return digest;
}

static void configure_cloud_init(const struct build_opts *o)
{
    step("seeding cloud-init");

    char seed[PATH_MAX + 64];
    snprintf(seed, sizeof seed, "%s/var/lib/cloud/seed/nocloud", o->mnt);
    run_ok("mkdir", "-p", seed, NULL);

    run_ok("mkdir", "-p", P("%s/etc/cloud/cloud.cfg.d", o->mnt), NULL);
    write_file(P("%s/etc/cloud/cloud.cfg.d/99-c2vm.cfg", o->mnt),
               "datasource_list: [ NoCloud, None ]\n");

    char stamp[32];
    time_t now = time(NULL);
    strftime(stamp, sizeof stamp, "%Y%m%d%H%M%S", gmtime(&now));

    write_file(P("%s/meta-data", seed),
               "instance-id: iid-c2vm-%s\n"
               "local-hostname: %s\n",
               stamp, o->hostname);

    /* Matched by prefix: the guest names its interface from PCI topology, so
       the name is not known at build time. */
    write_file(P("%s/network-config", seed),
               "version: 2\n"
               "ethernets:\n"
               "  primary:\n"
               "    match:\n"
               "      name: \"en*\"\n"
               "    dhcp4: true\n"
               "    dhcp6: false\n");

    char keyblock[8192] = "";
    if (o->ssh_key)
    {
        char *keys = read_small_file(o->ssh_key);
        size_t w = 0;

        for (char *l = strtok(keys, "\r\n"); l; l = strtok(NULL, "\r\n"))
        {
            while (*l == ' ' || *l == '\t')
                l++;
            if (*l == '\0' || *l == '#')
                continue;

            /* Quoted, because a key comment may contain '#'. Which means the
               two characters that would end the quote have to go. */
            if (strchr(l, '"') || strchr(l, '\\'))
                die("--ssh-key: %s contains a quote or backslash", o->ssh_key);

            if (w == 0)
                w = (size_t)snprintf(keyblock, sizeof keyblock,
                                     "    ssh_authorized_keys:\n");

            int n = snprintf(keyblock + w, sizeof keyblock - w,
                             "      - \"%s\"\n", l);
            if (n < 0 || (size_t)n >= sizeof keyblock - w)
                die("--ssh-key: %s has too many keys", o->ssh_key);
            w += (size_t)n;
        }

        if (w == 0)
            die("--ssh-key: %s contains no keys", o->ssh_key);

        free(keys);
    }

    /*
     * The seed ships inside a distributable disk, so it must never hold a
     * plaintext password.
     */
    char pwblock[512] = "";
    char *pwhash = NULL;
    if (o->pw_file)
    {
        char *plain = read_small_file(o->pw_file);
        if (plain[0] == '\0')
            die("--root-password: %s is empty", o->pw_file);

        pwhash = hash_password(plain);
        memset(plain, 0, strlen(plain));
        free(plain);

        snprintf(pwblock, sizeof pwblock,
                 "chpasswd:\n"
                 "  expire: true\n"
                 "  users:\n"
                 "    - name: root\n"
                 "      type: hash\n"
                 "      password: \"%s\"\n",
                 pwhash);

        fprintf(stderr,
                "c2vm: warning: --root-password sets a root password on a\n"
                "               distributable image. It is hashed and expired on\n"
                "               first login, and SSH password authentication stays\n"
                "               off, so it reaches only the serial console.\n");
    }

    if (!o->ssh_key && !o->pw_file)
        fprintf(stderr,
                "c2vm: warning: no --ssh-key and no --root-password: the guest\n"
                "               will boot with no way to log in.\n");

    write_file(P("%s/user-data", seed),
               "#cloud-config\n"
               "hostname: %s\n"
               "\n"
               "users:\n"
               "  - name: %s\n"
               "    groups: [adm, sudo]\n"
               "    shell: /bin/bash\n"
               "    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n"
               "    lock_passwd: true\n"
               "%s"
               "\n"
               "ssh_pwauth: false\n"
               "disable_root: %s\n"
               "%s"
               "\n"
               "ssh_deletekeys: true\n"
               "ssh_genkeytypes: [ed25519, rsa]\n",
               o->hostname, o->user, keyblock,
               pwhash ? "false" : "true", pwblock);

    run_ok("chmod", "0600", P("%s/user-data", seed), NULL);
    run_ok("chmod", "0700", seed, NULL);

    if (pwhash)
    {
        memset(pwhash, 0, strlen(pwhash));
        free(pwhash);
    }

    /*
     * systemd regenerates the machine ID on first boot. Without this every
     * clone of this disk answers to one identity, and a DHCP server hands
     * them all the same lease.
     */
    run_ok("truncate", "-s", "0", P("%s/etc/machine-id", o->mnt), NULL);
    run_ok("rm", "-f", P("%s/var/lib/dbus/machine-id", o->mnt), NULL);

    /* Same argument for host keys: baked-in keys would be shared by every VM
       built from this image. cloud-init writes fresh ones on first boot. */
    run_ok("find", P("%s/etc/ssh", o->mnt), "-name", "ssh_host_*", "-delete", NULL);

    /* The package preset normally enables these. Be explicit: a disk that
       silently ships a disabled cloud-init boots with no user and no network. */
    static const char *CI_UNITS[] = {
        "cloud-init-local.service",
        "cloud-init.service",
        "cloud-config.service",
        "cloud-final.service",
    };
    for (size_t i = 0; i < NELEMS(CI_UNITS); i++)
        run("chroot", o->mnt, "systemctl", "enable", CI_UNITS[i], NULL);
}

static void write_metadata(const struct build_opts *o)
{
    step("recording build metadata");

    char *digest = read_source_digest(o);
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
               "    \"compressed\": %s\n"
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
               "    \"user\": \"%s\",\n"
               "    \"extra_packages\": \"%s\",\n"
               "    \"ssh_key\": %s,\n"
               "    \"root_password\": %s\n"
               "  },\n"
               "  \"packages_before\": \"metadata/packages-before.txt\",\n"
               "  \"packages_after\": \"metadata/packages-after.txt\"\n"
               "}\n",
               J(C2VM_VERSION), J(stamp), J(host),
               J(o->image), J(digest),
               J(o->size), J(o->fstype), J(o->format),
               o->compress ? "true" : "false",
               J(o->kernel), J(kver),
               J(gver),
               J(o->hostname), J(o->user), J(o->packages ? o->packages : ""),
               o->ssh_key ? "true" : "false",
               o->pw_file ? "true" : "false");

    free(digest);
    free(kver);
    free(gver);
    free(host);
}

static void convert_formats(const struct build_opts *o)
{
    if (!has_format(o, "qcow2"))
        return;

    step("converting to qcow2%s", o->compress ? " (compressed)" : "");
    run_ok("qemu-img", "convert", "-f", "raw", "-O", "qcow2",
           o->compress ? "-c" : "-p",
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
    fprintf(stderr, "  user:     %s\n", o.user);
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
    configure_cloud_init(&o);
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
