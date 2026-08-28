#ifndef C2VM_CLEANUP_H
#define C2VM_CLEANUP_H

#include <sys/types.h>

// equivalent of `trap cleanup EXIT INT TERM`
void cleanup_init(void);
void cleanup_push_umount(const char *path);
void cleanup_push_guestunmount(const char *path);
void cleanup_push_losetup(const char *dev);
void cleanup_push_kill(pid_t pid, const char *what);
void cleanup_drop_kill(pid_t pid);
void cleanup_run(void);

#endif
