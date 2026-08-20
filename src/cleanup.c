#include "cleanup.h"
#include "run.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum action_kind { ACT_UMOUNT, ACT_LOSETUP };

struct action {
    enum action_kind kind;
    char path[4096];
};

#define MAX_ACTIONS 32

static struct action actions[MAX_ACTIONS];
static size_t action_count;

static void push(enum action_kind kind, const char *path)
{
    if (action_count >= MAX_ACTIONS)
        die("cleanup stack overflow (more than %d actions)", MAX_ACTIONS);

    struct action *a = &actions[action_count++];
    a->kind = kind;
    snprintf(a->path, sizeof a->path, "%s", path);
}

void cleanup_push_umount(const char *path)  { push(ACT_UMOUNT, path); }
void cleanup_push_losetup(const char *dev)  { push(ACT_LOSETUP, dev); }

/*
 * Drains the stack, so calling it twice is harmless — which matters because
 * both atexit() and the signal handler reach it.
 */
void cleanup_run(void)
{
    if (action_count > 0)
        step("cleanup");

    while (action_count > 0) {
        struct action *a = &actions[--action_count];
        switch (a->kind) {
        case ACT_UMOUNT:
            run("umount", "-R", a->path, NULL);
            break;
        case ACT_LOSETUP:
            run("losetup", "-d", a->path, NULL);
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
