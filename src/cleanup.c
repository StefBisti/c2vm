#include "cleanup.h"
#include "run.h"

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum action_kind
{
    ACT_UMOUNT,
    ACT_LOSETUP,
    ACT_KILL
};

struct action
{
    enum action_kind kind;
    char path[4096];
    pid_t pid;
};

#define MAX_ACTIONS 32

static struct action actions[MAX_ACTIONS];
static size_t action_count;

static struct action *push(enum action_kind kind, const char *path)
{
    if (action_count >= MAX_ACTIONS)
        die("cleanup stack overflow (more than %d actions)", MAX_ACTIONS);

    struct action *a = &actions[action_count++];
    a->kind = kind;
    a->pid = -1;
    snprintf(a->path, sizeof a->path, "%s", path);
    return a;
}

void cleanup_push_umount(const char *path) { push(ACT_UMOUNT, path); }
void cleanup_push_losetup(const char *dev) { push(ACT_LOSETUP, dev); }

/* A boot test that dies mid-run must not leave a VM holding the disk. */
void cleanup_push_kill(pid_t pid, const char *what) { push(ACT_KILL, what)->pid = pid; }

/*
 * The caller reaped the child itself. Without this the pid stays on the
 * stack and cleanup signals whatever the kernel has since reassigned it to.
 */
void cleanup_drop_kill(pid_t pid)
{
    for (size_t i = 0; i < action_count; i++)
        if (actions[i].kind == ACT_KILL && actions[i].pid == pid)
            actions[i].pid = -1;
}

/* Cheaper and quieter than shelling out to losetup just to query. */
static bool loop_attached(const char *dev)
{
    const char *name = strrchr(dev, '/');
    name = name ? name + 1 : dev;

    char path[PATH_MAX];
    snprintf(path, sizeof path, "/sys/block/%s/loop/backing_file", name);

    return access(path, F_OK) == 0;
}

/*
 * Drains the stack, so calling it twice is harmless — which matters because
 * both atexit() and the signal handler reach it.
 */
void cleanup_run(void)
{
    if (action_count > 0)
        step("cleanup");

    while (action_count > 0)
    {
        struct action *a = &actions[--action_count];
        switch (a->kind)
        {
        case ACT_UMOUNT:
            /* A lazy detach is better than leaving the mount behind. */
            if (run("umount", "-R", a->path, NULL) != 0)
                run("umount", "-R", "-l", a->path, NULL);
            break;
        case ACT_LOSETUP:
            /*
             * --partscan makes udev, and udisks2 on a desktop, open the
             * partition devices. Detaching while they are still open only
             * sets the kernel's autoclear flag and losetup reports success
             * while the device lingers. Settle first so those handles close.
             */
            run("udevadm", "settle", NULL);
            run("losetup", "-d", a->path, NULL);
            run("udevadm", "settle", NULL);
            if (loop_attached(a->path))
                fprintf(stderr,
                        "c2vm: warning: %s is still attached; "
                        "run: sudo losetup -d %s\n",
                        a->path, a->path);
            break;
        case ACT_KILL:
            if (a->pid > 0 && kill(a->pid, SIGTERM) == 0)
            {
                fprintf(stderr, "  killing %s (pid %d)\n", a->path, (int)a->pid);

                /* SIGKILL after a grace period: QEMU normally goes on TERM.
                   Reaping in the loop, so an exit ends the wait at once. */
                bool gone = false;
                for (int i = 0; i < 20 && !gone; i++)
                {
                    if (waitpid(a->pid, NULL, WNOHANG) != 0)
                        gone = true;
                    else
                        usleep(100000);
                }

                if (!gone)
                {
                    kill(a->pid, SIGKILL);
                    waitpid(a->pid, NULL, 0);
                }
            }
            break;
        }
    }
}

/*
 * Not strictly async-signal-safe (it forks and prints), but the alternative
 * is leaking loop devices and mounts on Ctrl-C, which is worse.
 */
static void on_signal(int sig)
{
    fprintf(stderr, "\nc2vm: interrupted by signal %d\n", sig);
    cleanup_run();
    _exit(128 + sig);
}

void cleanup_init(void)
{
    atexit(cleanup_run);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
}
