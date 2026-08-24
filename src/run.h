#ifndef C2VM_RUN_H
#define C2VM_RUN_H

#include <stdbool.h>

extern bool dry_run;

/* All take a NULL-terminated argument list: run("parted", "-s", disk, NULL) */

int run(const char *prog, ...);           /* returns exit status */
void run_ok(const char *prog, ...);       /* dies if the command fails */
char *run_capture(const char *prog, ...); /* trimmed stdout, caller frees */

void write_file(const char *path, const char *fmt, ...);
void step(const char *fmt, ...); /* progress heading */
void die(const char *fmt, ...);  /* error + cleanup + exit(1) */

/* Same, but for argument lists built at runtime (e.g. a package list). */
int run_argv(char *const argv[]);
void run_argv_ok(char *const argv[]);

const char *P(const char *fmt, ...);

#endif