#ifndef C2VM_CLEANUP_H
#define C2VM_CLEANUP_H

#include <sys/types.h>

// equivalent of trap cleanup EXIT INT TERM
void cleanup_init(void);

// unmounts path, lazily if it is busy
void cleanup_push_umount(const char *path);

// guestmount is FUSE: umount(8) is the wrong tool, so it needs its own action
void cleanup_push_guestunmount(const char *path);

// detaches the loop device dev
void cleanup_push_losetup(const char *dev);

// terminates pid, so a run that dies leaves no VM holding the disk
void cleanup_push_kill(pid_t pid, const char *what);

// cancels a pending kill, for a process that exited on its own
void cleanup_drop_kill(pid_t pid);

// runs every pending action, newest first, and drains the stack
void cleanup_run(void);

#endif
