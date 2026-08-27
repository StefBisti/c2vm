#include "build.h"
#include "cleanup.h"
#include "json.h"
#include "ova.h"
#include "run.h"

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    const char *backend;
    bool compress;
    char mnt[PATH_MAX];
    char root_uuid[64]; /* filled in by write_guest_config */

    /* Read while the chroot still exists, used once it is gone. */
    char kver[64]; // kernel version
    char gver[64]; // grub version
};

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
        "  --backend <name>       build backend (only: native)\n"
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
    o->backend = "native";
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
            else if (!strcmp(a, "--backend"))
                whereToWriteTheValue = &o->backend;

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

    if (!has_format(o, "qcow2") && !has_format(o, "raw") && !has_format(o, "ova"))
    {
        fprintf(stderr, "c2vm build: --format must include qcow2, raw or ova\n");
        return EXIT_USAGE;
    }
    if (strcmp(o->backend, "native") != 0)
    {
        fprintf(stderr, "c2vm build: unknown backend '%s' (only: native)\n",
                o->backend);
        return EXIT_USAGE;
    }

    if (o->ssh_key && !readable("--ssh-key", o->ssh_key))
        return EXIT_USAGE;
    if (o->pw_file && !readable("--root-password", o->pw_file))
        return EXIT_USAGE;

    return 0;
}

#pragma region STAGES

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

    char *digest = run_capture("src/extract-rootfs.sh", o->image, P("%s/rootfs", o->outdir), NULL);
    char *host = run_capture("uname", "-srm", NULL);

    if (!dry_run && strncmp(digest, "sha256:", 7) != 0)
        die("extract-rootfs.sh did not return a digest: %.60s", digest);

    char stamp[32];
    time_t now = time(NULL);
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    write_file(P("%s/metadata/source.json", o->outdir),
               "{\n"
               "  \"source_image\": \"%s\",\n"
               "  \"source_digest\": \"%s\",\n"
               "  \"extracted_at\": \"%s\",\n"
               "  \"extracted_by\": \"c2vm/%s\",\n"
               "  \"host\": \"%s\"\n"
               "}\n",
               J(o->image), J(digest), J(stamp), J(C2VM_VERSION), J(host));

    free(digest);
    free(host);
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

    char *loop = run_capture("losetup", "--find", "--show", "--partscan", P("%s/disk.raw", o->outdir), NULL);
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

    run_ok("rsync", "-aHAX", "--numeric-ids", P("%s/rootfs/", o->outdir), P("%s/", o->mnt), NULL);

    run_ok("mkdir", "-p", P("%s/boot/efi", o->mnt), NULL);
    run_ok("mount", P("%sp1", loop), P("%s/boot/efi", o->mnt), NULL);
    cleanup_push_umount(P("%s/boot/efi", o->mnt));

    static const char *BINDS[] = {"dev", "dev/pts", "proc", "sys", "run"};
    for (size_t i = 0; i < NELEMS(BINDS); i++)
    {
        const char *target = P("%s/%s", o->mnt, BINDS[i]);
        run_ok("mount", "--bind", P("/%s", BINDS[i]), target, NULL);
        run_ok("mount", "--make-rslave", target, NULL);
        cleanup_push_umount(target);
    }

    run_ok("cp", "/etc/resolv.conf", P("%s/etc/resolv.conf", o->mnt), NULL);
}

static void write_guest_config(struct build_opts *o, const char *loop)
{
    step("writing guest configuration");

    write_file(P("%s/usr/sbin/policy-rc.d", o->mnt), "#!/bin/sh\nexit 101\n");
    run_ok("chmod", "0755", P("%s/usr/sbin/policy-rc.d", o->mnt), NULL);

    char *root_uuid = run_capture("blkid", "-s", "UUID", "-o", "value", P("%sp2", loop), NULL);
    char *esp_uuid = run_capture("blkid", "-s", "UUID", "-o", "value", P("%sp1", loop), NULL);

    write_file(P("%s/etc/fstab", o->mnt),
               "# <device> <mount> <fs> <options> <dump> <pass>\n"
               "UUID=%s / %s defaults 0 1\n"
               "UUID=%s /boot/efi vfat umask=0077 0 1\n",
               root_uuid, o->fstype, esp_uuid);

    snprintf(o->root_uuid, sizeof o->root_uuid, "%s", root_uuid);

    write_file(P("%s/etc/hostname", o->mnt), "%s\n", o->hostname);
    write_file(P("%s/etc/hosts", o->mnt), "127.0.0.1\tlocalhost\n"
                                          "127.0.1.1\t%s\n",
               o->hostname);

    free(root_uuid);
    free(esp_uuid);
}

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
            if (n >= NELEMS(argv) - 1)
                die("too many packages (limit is %zu)", NELEMS(argv) - 1);
            argv[n++] = t;
        }

    argv[n] = NULL;
    run_argv_ok(argv);
    free(extra);
}

// writes build/metadata/packages-before.txt and build/metadata/packages-after.txt,
// build/mnt gets a kernel, GRUB installed, serial console enabled
static void install_system(struct build_opts *o)
{
    step("installing kernel, bootloader and init");

    run_ok("chroot", o->mnt, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", NULL);

    char *before = run_capture("chroot", o->mnt, "dpkg-query", "-W", "-f=${Package}\t${Version}\n", NULL);
    write_file(P("%s/metadata/packages-before.txt", o->outdir), "%s\n", before);
    free(before);

    apt_install(o);

    write_file(P("%s/etc/initramfs-tools/modules", o->mnt), "%s", VIRTIO_MODULES);
    run_ok("chroot", o->mnt, "update-initramfs", "-u", "-k", "all", NULL);

    write_file(P("%s/etc/default/grub", o->mnt),
               "GRUB_TIMEOUT=5\n"
               "GRUB_TERMINAL=\"console serial\"\n"
               "GRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200\"\n"
               "GRUB_CMDLINE_LINUX_DEFAULT=\"\"\n"
               "GRUB_CMDLINE_LINUX=\"console=tty0 console=ttyS0,115200n8\"\n");

    run_ok("chroot", o->mnt, "grub-install", "--removable", "--no-nvram", "--target=x86_64-efi", "--efi-directory=/boot/efi", "--boot-directory=/boot", NULL);
    run_ok("chroot", o->mnt, "update-grub", NULL);

    run_ok("mkdir", "-p", P("%s/boot/efi/boot/grub", o->mnt), NULL);
    write_file(P("%s/boot/efi/boot/grub/grub.cfg", o->mnt), "set prefix=($root)/boot/grub\n"
                                                            "configfile $prefix/grub.cfg\n");

    run_ok("chroot", o->mnt, "systemctl", "enable", "serial-getty@ttyS0.service", NULL);

    char *after = run_capture("chroot", o->mnt, "dpkg-query", "-W", "-f=${Package}\t${Version}\n", NULL);
    write_file(P("%s/metadata/packages-after.txt", o->outdir), "%s\n", after);
    free(after);

    /* Read here rather than in write_metadata: build.json is written after
       the disk has been converted now, by which point the chroot is gone. */
    char *kver = run_capture("chroot", o->mnt, "dpkg-query", "-W", "-f=${Version}", o->kernel, NULL);
    char *gver = run_capture("chroot", o->mnt, "dpkg-query", "-W", "-f=${Version}", "grub-efi-amd64", NULL);
    snprintf(o->kver, sizeof o->kver, "%s", kver);
    snprintf(o->gver, sizeof o->gver, "%s", gver);
    free(kver);
    free(gver);

    run_ok("chroot", o->mnt, "apt-get", "clean", NULL);
    run_ok("rm", "-f", P("%s/usr/sbin/policy-rc.d", o->mnt), NULL);
    run_ok("rm", "-f", P("%s/etc/resolv.conf", o->mnt), NULL);
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
    char *json = read_file(path, 8192);

    char *digest = json_get(json, "source_digest");
    free(json);
    if (!digest)
        die("%s does not contain a source_digest", path);
    return digest;
}

/* Builds the authorized_keys block of the user-data, or "" for no key. */
static void ssh_key_block(const struct build_opts *o, char *out, size_t cap)
{
    out[0] = '\0';
    if (!o->ssh_key)
        return;

    char *keys = read_file(o->ssh_key, 8192);
    size_t w = 0;

    for (char *l = strtok(keys, "\r\n"); l; l = strtok(NULL, "\r\n"))
    {
        while (*l == ' ' || *l == '\t')
            l++;
        if (*l == '\0' || *l == '#')
            continue;

        if (strchr(l, '"') || strchr(l, '\\'))
            die("--ssh-key: %s contains a quote or backslash", o->ssh_key);

        if (w == 0)
            w = (size_t)snprintf(out, cap, "    ssh_authorized_keys:\n");

        int n = snprintf(out + w, cap - w, "      - \"%s\"\n", l);
        if (n < 0 || (size_t)n >= cap - w)
            die("--ssh-key: %s has too many keys", o->ssh_key);
        w += (size_t)n;
    }

    if (w == 0)
        die("--ssh-key: %s contains no keys", o->ssh_key);

    free(keys);
}

static void reset_identity(const struct build_opts *o)
{
    run_ok("truncate", "-s", "0", P("%s/etc/machine-id", o->mnt), NULL);
    run_ok("rm", "-f", P("%s/var/lib/dbus/machine-id", o->mnt), NULL);
    run_ok("find", P("%s/etc/ssh", o->mnt), "-name", "ssh_host_*", "-delete", NULL);
}

static void enable_cloud_init(const struct build_opts *o)
{
    run_ok("mkdir", "-p", P("%s/etc/cloud/cloud.cfg.d", o->mnt), NULL);
    write_file(P("%s/etc/cloud/cloud.cfg.d/99-c2vm.cfg", o->mnt), "datasource_list: [ NoCloud, None ]\n");

    /* The package preset normally enables these. */
    static const char *CI_UNITS[] = {
        "cloud-init-local.service",
        "cloud-init.service",
        "cloud-config.service",
        "cloud-final.service",
    };
    for (size_t i = 0; i < NELEMS(CI_UNITS); i++)
        run("chroot", o->mnt, "systemctl", "enable", CI_UNITS[i], NULL);
}

static void configure_cloud_init(const struct build_opts *o)
{
    step("seeding cloud-init");

    enable_cloud_init(o);

    char seed[PATH_MAX + 64];
    snprintf(seed, sizeof seed, "%s/var/lib/cloud/seed/nocloud", o->mnt);
    run_ok("mkdir", "-p", seed, NULL);

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

    char keyblock[8192];
    ssh_key_block(o, keyblock, sizeof keyblock);

    /*
     * The seed ships inside a distributable disk, so it must never hold a
     * plaintext password.
     */
    char pwblock[512] = "";
    char *pwhash = NULL;
    if (o->pw_file)
    {
        char *plain = read_file(o->pw_file, 8192);
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

    reset_identity(o);
}

static void artifact_list(const struct build_opts *o, char *out, size_t cap)
{
    static const char *NAMES[] = {"disk.raw", "disk.qcow2", "disk.ova"};

    out[0] = '\0';
    size_t w = 0;
    const char *sep = "";

    for (size_t i = 0; i < NELEMS(NAMES); i++)
    {
        const char *path = P("%s/%s", o->outdir, NAMES[i]);

        struct stat st;
        if (dry_run || stat(path, &st) != 0)
            continue;

        char *sum = run_capture("sha256sum", path, NULL);
        char *sp = strchr(sum, ' ');
        if (sp)
            *sp = '\0';

        int n = snprintf(out + w, cap - w,
                         "%s    { \"name\": \"%s\", \"sha256\": \"%s\","
                         " \"size\": %llu }",
                         sep, J(NAMES[i]), J(sum),
                         (unsigned long long)st.st_size);
        free(sum);

        if (n < 0 || (size_t)n >= cap - w)
            die("artefact list does not fit in %zu bytes", cap);

        w += (size_t)n;
        sep = ",\n";
    }
}

static void write_metadata(const struct build_opts *o)
{
    step("recording build metadata");

    char *digest = read_source_digest(o);
    char *host = run_capture("uname", "-srm", NULL);

    char arts[2048];
    artifact_list(o, arts, sizeof arts);

    if (!dry_run && strncmp(digest, "sha256:", 7) != 0)
        die("%s/metadata/source.json holds no digest: %.60s",
            o->outdir, digest);

    char stamp[32];
    time_t now = time(NULL);
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    write_file(P("%s/metadata/build.json", o->outdir),
               "{\n"
               "  \"c2vm_version\": \"%s\",\n"
               "  \"built_at\": \"%s\",\n"
               "  \"backend\": \"%s\",\n"
               "  \"host_kernel\": \"%s\",\n"
               "  \"source\": {\n"
               "    \"image\": \"%s\",\n"
               "    \"digest\": \"%s\"\n"
               "  },\n"
               "  \"disk\": {\n"
               "    \"size\": \"%s\",\n"
               "    \"fstype\": \"%s\",\n"
               "    \"formats\": \"%s\",\n"
               "    \"compressed\": %s,\n"
               "    \"root_uuid\": \"%s\"\n"
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
               "  \"artifacts\": [\n%s\n  ],\n"
               "  \"packages_before\": \"metadata/packages-before.txt\",\n"
               "  \"packages_after\": \"metadata/packages-after.txt\"\n"
               "}\n",
               J(C2VM_VERSION), J(stamp), J(o->backend), J(host),
               J(o->image), J(digest),
               J(o->size), J(o->fstype), J(o->format),
               o->compress ? "true" : "false", J(o->root_uuid),
               J(o->kernel), J(o->kver),
               J(o->gver),
               J(o->hostname), J(o->user), J(o->packages ? o->packages : ""),
               o->ssh_key ? "true" : "false",
               o->pw_file ? "true" : "false",
               arts);

    free(digest);
    free(host);
}

static void convert_formats(const struct build_opts *o)
{
    if (has_format(o, "qcow2"))
    {
        step("converting to qcow2%s", o->compress ? " (compressed)" : "");
        run_ok("qemu-img", "convert", "-f", "raw", "-O", "qcow2",
               o->compress ? "-c" : "-p",
               P("%s/disk.raw", o->outdir), P("%s/disk.qcow2", o->outdir), NULL);
    }

    if (has_format(o, "ova"))
        ova_write(o->outdir, o->hostname);
}

#pragma endregion STAGES

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

    /* Unmount and detach before converting, so qcow2 sees a quiesced disk. */
    cleanup_run();
    free(loop);

    convert_formats(&o);

    /* Last, so that it can record the hash of every artefact above. */
    write_metadata(&o);

    step("done");
    fprintf(stderr, "  %s/disk.raw\n", o.outdir);
    if (has_format(&o, "qcow2"))
        fprintf(stderr, "  %s/disk.qcow2\n", o.outdir);
    if (has_format(&o, "ova"))
        fprintf(stderr, "  %s/disk.ova\n", o.outdir);
    fprintf(stderr, "  %s/metadata/build.json\n", o.outdir);

    return EXIT_SUCCESS;
}
