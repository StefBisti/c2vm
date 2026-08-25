#include "boottest.h"
#include "cleanup.h"
#include "run.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EXIT_USAGE 2

static const char *OVMF_CODE = "/usr/share/OVMF/OVMF_CODE_4M.fd";
static const char *OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd";

struct test_opts
{
    const char *artifact;
    const char *ssh_key;
    const char *user;
    const char *outdir;
    const char *port;
    int timeout;
    bool kvm;
    char *meta; /* metadata/build.json, read once */
};

static void test_usage(void)
{
    fputs(
        "usage: c2vm boot-test <artifact> [options]\n"
        "\n"
        "  --ssh-key <path>    private key matching the one built into the image\n"
        "  --user <name>       guest account (default: the one build.json records)\n"
        "  --out <dir>         directory holding metadata/build.json (default: build)\n"
        "  --port <n>          host port forwarded to guest 22 (default: 2222)\n"
        "  --timeout <sec>     hard limit, tripled without KVM (default: 180)\n",
        stderr);
}

static char *json_get(const char *json, const char *key)
{
    char *k = strstr(json, P("\"%s\"", key));
    if (!k)
        return NULL;

    char *val = strchr(k + strlen(key) + 2, '"');
    if (!val)
        return NULL;

    char *end = strchr(val + 1, '"');
    if (!end)
        return NULL;

    size_t n = (size_t)(end - val - 1);
    char *out = malloc(n + 1);
    if (!out)
        die("out of memory");
    memcpy(out, val + 1, n);
    out[n] = '\0';

    return out;
}

static char *json_get_in(const char *json, const char *section, const char *key)
{
    const char *from = strstr(json, P("\"%s\"", section));
    if (!from)
        return NULL;

    return json_get(from, key);
}

static char *read_all(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        die("cannot read %s: %s", path, strerror(errno));

    char buf[65536];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    bool overflow = fgetc(f) != EOF; /* anything left over means it is short */
    fclose(f);

    if (overflow)
        die("%s is larger than %zu bytes", path, sizeof buf - 1);
    buf[n] = '\0';

    /* A NUL would end the string early and the assertions would then report
       a missing field rather than a corrupt file. */
    if (strlen(buf) != n)
        die("%s contains a NUL byte", path);

    return strdup(buf);
}

static bool has_suffix(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && !strcmp(s + n - m, suffix);
}

/* qemu wants to be told, and guessing from content would need a probe. */
static const char *disk_format(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
    {
        fprintf(stderr, "c2vm boot-test: cannot tell the format of %s "
                        "from its name\n",
                path);
        return NULL;
    }

    if (!strcmp(dot, ".qcow2"))
        return "qcow2";
    if (!strcmp(dot, ".raw") || !strcmp(dot, ".img"))
        return "raw";
    if (!strcmp(dot, ".vmdk"))
        return "vmdk";

    fprintf(stderr, "c2vm boot-test: unsupported artifact type '%s'\n", dot);
    return NULL;
}

static const char *unpack_ova(const struct test_opts *t)
{
    step("extracting the disk from %s", t->artifact);

    const char *dir = P("%s/boot-test", t->outdir);
    run_ok("mkdir", "-p", dir, NULL);
    /* c2vm packs exactly this member. A third-party OVA names its disk
       whatever its OVF References section says, which is not read here. */
    if (run("tar", "-xf", t->artifact, "-C", dir, "disk.vmdk", NULL) != 0)
        die("%s has no disk.vmdk member; boot-test reads OVAs c2vm built",
            t->artifact);

    /*
     * streamOptimized is compressed and append-only: qemu reads it but
     * cannot write to it, and a guest whose root filesystem is read-only
     * never gets through cloud-init. Boot a qcow2 overlay so writes land
     * beside the disk while every read still comes from the VMDK.
     */
    const char *overlay = P("%s/overlay.qcow2", dir);
    run_ok("rm", "-f", overlay, NULL);
    run_ok("qemu-img", "create", "-f", "qcow2",
           "-b", "disk.vmdk", "-F", "vmdk", overlay, NULL);

    return P("%s/overlay.qcow2", dir);
}

static pid_t spawn_qemu(const struct test_opts *t, const char *disk,
                        const char *logpath)
{
    const char *vars = P("%s/boot-test-VARS.fd", t->outdir);
    run_ok("cp", OVMF_VARS, vars, NULL);

    /* qemu truncates the file itself, but not before the first poll can read
       it. A log left by the previous run would otherwise satisfy the serial
       half of the test before this boot has written a byte. */
    run_ok("rm", "-f", logpath, NULL);

    char *argv[40];
    size_t n = 0;

    argv[n++] = "qemu-system-x86_64";
    argv[n++] = "-machine";
    argv[n++] = "q35";

    if (t->kvm)
    {
        argv[n++] = "-enable-kvm";
        argv[n++] = "-cpu";
        argv[n++] = "host";
    }
    else
    {
        argv[n++] = "-accel";
        argv[n++] = "tcg";
    }

    argv[n++] = "-m";
    argv[n++] = "2048";
    argv[n++] = "-smp";
    argv[n++] = "2";

    argv[n++] = "-drive";
    argv[n++] = (char *)P("if=pflash,format=raw,readonly=on,file=%s", OVMF_CODE);
    argv[n++] = "-drive";
    argv[n++] = (char *)P("if=pflash,format=raw,file=%s", vars);

    argv[n++] = "-drive";
    argv[n++] = (char *)P("file=%s,format=%s,if=virtio", disk, disk_format(disk));

    argv[n++] = "-netdev";
    argv[n++] = (char *)P("user,id=net0,hostfwd=tcp::%s-:22", t->port);
    argv[n++] = "-device";
    argv[n++] = "virtio-net-pci,netdev=net0";

    argv[n++] = "-display";
    argv[n++] = "none";
    argv[n++] = "-serial";
    argv[n++] = (char *)P("file:%s", logpath);

    /* A guest that panics and reboots would otherwise loop until timeout. */
    argv[n++] = "-no-reboot";
    argv[n] = NULL;

    fputs("  +", stderr);
    for (size_t i = 0; argv[i]; i++)
        fprintf(stderr, " %s", argv[i]);
    fputc('\n', stderr);

    pid_t pid = fork();
    if (pid < 0)
        die("fork: %s", strerror(errno));

    if (pid == 0)
    {
        execvp(argv[0], argv);
        fprintf(stderr, "c2vm: cannot execute %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    cleanup_push_kill(pid, "qemu");
    return pid;
}

static void ssh_argv(const struct test_opts *t, const char *cmd, char *argv[])
{
    size_t n = 0;

    argv[n++] = "ssh";
    argv[n++] = "-p";
    argv[n++] = (char *)t->port;
    argv[n++] = "-i";
    argv[n++] = (char *)t->ssh_key;
    argv[n++] = "-o";
    argv[n++] = "StrictHostKeyChecking=no";
    argv[n++] = "-o";
    argv[n++] = "UserKnownHostsFile=/dev/null";
    argv[n++] = "-o";
    argv[n++] = "BatchMode=yes";
    argv[n++] = "-o";
    argv[n++] = "ConnectTimeout=5";
    argv[n++] = "-o";
    argv[n++] = "LogLevel=ERROR";
    argv[n++] = (char *)P("%s@127.0.0.1", t->user);
    argv[n++] = (char *)cmd;
    argv[n] = NULL;
}

static int ssh_try(const struct test_opts *t, const char *cmd)
{
    char *argv[24];
    ssh_argv(t, cmd, argv);

    /* Quiet: this runs in a poll loop and most attempts fail by design. */
    int devnull = open("/dev/null", O_WRONLY);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    if (devnull >= 0)
    {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
    }

    int rc = run_argv(argv);

    if (devnull >= 0)
    {
        dup2(saved_out, STDOUT_FILENO);
        dup2(saved_err, STDERR_FILENO);
        close(devnull);
    }
    close(saved_out);
    close(saved_err);

    return rc;
}

static char *ssh_out(const struct test_opts *t, const char *cmd)
{
    char *argv[24];
    ssh_argv(t, cmd, argv);

    char *out = NULL;
    int rc = run_argv_capture(argv, &out);
    if (rc != 0)
        die("guest command failed (exit %d): %s", rc, cmd);

    return out;
}

/* The serial console is the half of the test that does not depend on the
   network working, which is why both halves are required. */
static bool serial_shows_login(const char *logpath)
{
    FILE *f = fopen(logpath, "r");
    if (!f)
        return false;

    char line[4096];
    bool found = false;
    while (!found && fgets(line, sizeof line, f))
        if (strstr(line, "login:"))
            found = true;

    fclose(f);
    return found;
}

static void print_tail(const char *logpath, int lines)
{
    fprintf(stderr, "\n--- last %d lines of %s ---\n", lines, logpath);
    run("tail", "-n", P("%d", lines), logpath, NULL);
    fputs("--- end ---\n", stderr);
}

static void wait_for_boot(const struct test_opts *t, pid_t qemu,
                          const char *logpath)
{
    step("waiting for the guest (timeout %ds, %s)", t->timeout,
         t->kvm ? "kvm" : "tcg");

    time_t deadline = time(NULL) + t->timeout;
    bool saw_login = false;

    while (time(NULL) < deadline)
    {
        int status = 0;
        if (waitpid(qemu, &status, WNOHANG) == qemu)
        {
            cleanup_drop_kill(qemu);
            print_tail(logpath, 50);
            die("qemu exited before the guest came up");
        }

        if (!saw_login && serial_shows_login(logpath))
        {
            saw_login = true;
            fputs("  serial: login prompt reached\n", stderr);
        }

        if (saw_login && ssh_try(t, "true") == 0)
        {
            fputs("  ssh:    command executed\n", stderr);
            return;
        }

        sleep(2);
    }

    print_tail(logpath, 50);
    fprintf(stderr, "c2vm: timed out after %ds (serial login: %s)\n",
            t->timeout, saw_login ? "yes" : "no");
    exit(EXIT_BOOT_TIMEOUT);
}

static void check(const char *what, bool ok, const char *detail)
{
    fprintf(stderr, "  [%s] %-22s %s\n", ok ? "ok" : "FAIL", what, detail);
    if (!ok)
        die("assertion failed: %s", what);
}

static void assert_guest(const struct test_opts *t)
{
    step("checking the guest");

    char *want_uuid = json_get_in(t->meta, "disk", "root_uuid");
    char *kernel_pkg = json_get_in(t->meta, "kernel", "package");
    char *want_kver = json_get_in(t->meta, "kernel", "version");

    if (!want_uuid || !kernel_pkg || !want_kver)
        die("%s/metadata/build.json is missing fields boot-test needs; "
            "rebuild with this version of c2vm",
            t->outdir);

    /* degraded is accepted: a converted container legitimately carries units
       that have nothing to do on a VM and fail. */
    /* ssh.socket accepts a connection while the system is still starting, so
       the first probe can arrive mid cloud-init. --wait blocks until startup
       finishes; the outer timeout keeps a hung unit from stalling the test. */
    char *state = ssh_out(t, "timeout 60 systemctl is-system-running --wait "
                             "|| true");
    check("systemd state", !strcmp(state, "running") || !strcmp(state, "degraded"),
          state);

    char *uuid = ssh_out(t, "findmnt -no UUID /");
    check("root fs uuid", want_uuid && !strcmp(uuid, want_uuid), uuid);

    char *addr = ssh_out(t, "ip -4 -o addr show scope global | awk '{print $4}'");
    check("network address", addr[0] != '\0', addr[0] ? addr : "(none)");

    char *kver = ssh_out(t, P("dpkg-query -W -f='${Version}' %s",
                              kernel_pkg ? kernel_pkg : "linux-image-virtual"));
    check("kernel package", want_kver && !strcmp(kver, want_kver), kver);

    char *uname = ssh_out(t, "uname -r");
    fprintf(stderr, "  [--] %-22s %s\n", "running kernel", uname);

    free(want_uuid);
    free(kernel_pkg);
    free(want_kver);
    free(state);
    free(uuid);
    free(addr);
    free(kver);
    free(uname);
}

static int parse_opts(int argc, char *argv[], struct test_opts *t)
{
    t->artifact = NULL;
    t->ssh_key = NULL;
    t->user = NULL; /* resolved from build.json unless --user says otherwise */
    t->meta = NULL;
    t->outdir = "build";
    t->port = "2222";
    t->timeout = 180;

    for (int i = 0; i < argc; i++)
    {
        const char *a = argv[i];

        if (!strcmp(a, "-h") || !strcmp(a, "--help"))
        {
            test_usage();
            exit(EXIT_SUCCESS);
        }

        if (a[0] == '-')
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "c2vm boot-test: %s needs a value\n", a);
                return EXIT_USAGE;
            }
            const char *v = argv[++i];

            if (!strcmp(a, "--ssh-key"))
                t->ssh_key = v;
            else if (!strcmp(a, "--user"))
                t->user = v;
            else if (!strcmp(a, "--out"))
                t->outdir = v;
            else if (!strcmp(a, "--port"))
                t->port = v;
            else if (!strcmp(a, "--timeout"))
                t->timeout = atoi(v);
            else
            {
                fprintf(stderr, "c2vm boot-test: unknown option '%s'\n", a);
                return EXIT_USAGE;
            }
            continue;
        }

        if (t->artifact)
        {
            fprintf(stderr, "c2vm boot-test: unexpected argument '%s'\n", a);
            return EXIT_USAGE;
        }
        t->artifact = a;
    }

    if (!t->artifact)
    {
        fprintf(stderr, "c2vm boot-test: no artifact given\n");
        test_usage();
        return EXIT_USAGE;
    }

    if (!t->ssh_key)
    {
        fprintf(stderr, "c2vm boot-test: --ssh-key is required\n");
        return EXIT_USAGE;
    }

    /* Tripled later for TCG, so the cap leaves room for that without
       overflowing into a deadline in the past. */
    if (t->timeout <= 0 || t->timeout > 86400)
    {
        fprintf(stderr, "c2vm boot-test: --timeout must be 1..86400\n");
        return EXIT_USAGE;
    }

    if (access(t->artifact, R_OK) != 0)
    {
        fprintf(stderr, "c2vm boot-test: cannot read %s: %s\n",
                t->artifact, strerror(errno));
        return EXIT_USAGE;
    }
    if (access(t->ssh_key, R_OK) != 0)
    {
        fprintf(stderr, "c2vm boot-test: cannot read %s: %s\n",
                t->ssh_key, strerror(errno));
        return EXIT_USAGE;
    }
    if (!has_suffix(t->artifact, ".ova") && !disk_format(t->artifact))
        return EXIT_USAGE;

    return 0;
}

int cmd_boot_test(int argc, char *argv[])
{
    struct test_opts t;
    int rc = parse_opts(argc, argv, &t);
    if (rc != 0)
        return rc;

    /* A CI runner without nested virtualisation still has to be able to run
       this, and TCG is roughly an order of magnitude slower. */
    t.kvm = access("/dev/kvm", R_OK | W_OK) == 0;
    if (!t.kvm)
    {
        t.timeout *= 3;
        fprintf(stderr,
                "c2vm: warning: /dev/kvm unavailable, falling back to tcg;\n"
                "               timeout raised to %ds\n",
                t.timeout);
    }

    t.meta = read_all(P("%s/metadata/build.json", t.outdir));

    /* Which account exists in the guest is a build decision, not a test
       parameter. Read it back rather than guessing, the same way every
       assertion below does. */
    if (!t.user)
    {
        t.user = json_get_in(t.meta, "flags", "user");
        if (!t.user)
            die("%s/metadata/build.json records no user; pass --user", t.outdir);
    }
    fprintf(stderr, "  user:     %s\n", t.user);

    cleanup_init();

    /* Both outlive dozens of further P() calls — every ssh attempt makes one
       — so they get real storage rather than a slot in the rotating pool. */
    char disk[PATH_MAX];
    snprintf(disk, sizeof disk, "%s",
             has_suffix(t.artifact, ".ova") ? unpack_ova(&t) : t.artifact);

    char logpath[PATH_MAX];
    snprintf(logpath, sizeof logpath, "%s/boot-test.log", t.outdir);

    step("booting %s", disk);
    pid_t qemu = spawn_qemu(&t, disk, logpath);

    wait_for_boot(&t, qemu, logpath);
    assert_guest(&t);

    step("boot test passed");
    fprintf(stderr, "  serial log: %s\n", logpath);

    /* cleanup_run() kills qemu; atexit would too, but say so explicitly. */
    cleanup_run();
    return EXIT_SUCCESS;
}
