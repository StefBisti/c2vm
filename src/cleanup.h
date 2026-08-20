#ifndef C2VM_CLEANUP_H
#define C2VM_CLEANUP_H

/* The C equivalent of `trap cleanup EXIT INT TERM`. Actions unwind LIFO. */

void cleanup_init(void);
void cleanup_push_umount(const char *path);
void cleanup_push_losetup(const char *dev);
void cleanup_run(void);

#endif
