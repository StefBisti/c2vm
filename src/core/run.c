#include "core/run.h"

#include "core/util.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
            len--; // remove trailing new lines
        buf[len] = '\0';
        *out = buf;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        die("waitpid: %s", strerror(errno));

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int run(const char *prog, ...)
{
    char *argv[MAX_ARGS];
    va_list ap;
    va_start(ap, prog);
    collect(prog, ap, argv);
    va_end(ap);
    return spawn(argv, NULL);
}

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
