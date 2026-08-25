#include "run.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

bool dry_run = false;

#define MAX_ARGS 64

// Packs ex. ("parted", "-s", "disk.raw", NULL) into an array execvp can use
static void collect(const char *prog, va_list ap, char *argv[])
{
    size_t n = 0;
    argv[n++] = (char *)prog;
    while (1)
    {
        const char *a = va_arg(ap, const char *);
        if (!a)
        {
            break;
        }
        if (n + 1 >= MAX_ARGS)
        {
            die("too many arguments");
        }
        argv[n++] = (char *)a;
    }
    argv[n] = NULL;
}

static void echo(char *const argv[])
{
    fputs(dry_run ? "  would run:" : "  +", stderr);
    for (size_t i = 0; argv[i]; i++)
        fprintf(stderr, " %s", argv[i]);
    fputc('\n', stderr);
}

/*
 * Fork and exec argv. If out is non-NULL the child's stdout is captured
 * into a malloc'd string and stored there, trailing newline stripped.
 */

// out = second return value
static int spawn(char *const argv[], char **out)
{
    echo(argv);

    if (dry_run)
    {
        if (out)
            *out = strdup("DRYRUN");
        return 0;
    }

    int fds[2] = {-1, -1};
    if (out && pipe(fds) != 0)
        die("pipe: %s", strerror(errno));

    pid_t pid = fork();
    if (pid < 0)
        die("fork: %s", strerror(errno));

    if (pid == 0)
    {
        if (out)
        {
            dup2(fds[1], STDOUT_FILENO);
            close(fds[0]);
            close(fds[1]);
        }
        execvp(argv[0], argv);
        fprintf(stderr, "c2vm: cannot execute %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    if (out)
    {
        close(fds[1]);
        size_t cap = 4096, len = 0;
        char *buf = malloc(cap);
        if (!buf)
            die("out of memory");
        for (;;)
        {
            if (len + 1 >= cap)
            {
                cap *= 2;
                char *grown = realloc(buf, cap);
                if (!grown)
                    die("out of memory");
                buf = grown;
            }
            ssize_t got = read(fds[0], buf + len, cap - len - 1);
            if (got <= 0)
                break;
            len += (size_t)got;
        }
        close(fds[0]);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == ' '))
            len--; /* blkid and skopeo both add a trailing newline */
        buf[len] = '\0';
        *out = buf;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        die("waitpid: %s", strerror(errno));

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

// run a command. Give me the exit code. I'll decide what to do.
int run(const char *prog, ...)
{
    char *argv[MAX_ARGS];
    va_list ap;
    va_start(ap, prog);
    collect(prog, ap, argv);
    va_end(ap);
    return spawn(argv, NULL);
}

// run a command. If it fails, kill the whole build.
void run_ok(const char *prog, ...)
{
    char *argv[MAX_ARGS];
    va_list ap;
    va_start(ap, prog);
    collect(prog, ap, argv);
    va_end(ap);

    int rc = spawn(argv, NULL);
    if (rc != 0)
        die("%s failed (exit %d)", prog, rc);
}

// run a command, hand me back what it printed
char *run_capture(const char *prog, ...)
{
    char *argv[MAX_ARGS];
    va_list ap;
    va_start(ap, prog);
    collect(prog, ap, argv);
    va_end(ap);

    char *out = NULL;
    int rc = spawn(argv, &out);
    if (rc != 0)
        die("%s failed (exit %d)", prog, rc);
    return out;
}

int run_argv(char *const argv[])
{
    return spawn(argv, NULL);
}

/* Like run_capture, but for an argv built at runtime. Returns the exit
   status instead of dying, so a caller can accept a non-zero one. */
int run_argv_capture(char *const argv[], char **out)
{
    return spawn(argv, out);
}

void run_argv_ok(char *const argv[])
{
    int rc = spawn(argv, NULL);
    if (rc != 0)
        die("%s failed (exit %d)", argv[0], rc);
}

// write a file from a format string
void write_file(const char *path, const char *fmt, ...)
{
    fprintf(stderr, dry_run ? "  would write: %s\n" : "  > %s\n", path);
    if (dry_run)
        return;

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

// prints a section heading so build output is readable
void step(const char *fmt, ...)
{
    fputs("\n==> ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// print an error and quit. Cleanup runs automatically
void die(const char *fmt, ...)
{
    fputs("c2vm: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE); /* atexit handler unwinds mounts and loop devices */
}

// useful because it requires no buffer for formatting
const char *P(const char *fmt, ...)
{
    static char pool[8][PATH_MAX];
    static size_t next;

    char *buf = pool[next];
    next = (next + 1) % (sizeof pool / sizeof pool[0]);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, PATH_MAX, fmt, ap);
    va_end(ap);

    return buf;
}
