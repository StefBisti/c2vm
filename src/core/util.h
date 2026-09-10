#ifndef C2VM_UTIL_H
#define C2VM_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#define C2VM_VERSION "0.1.0"

#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

#define EXIT_USAGE 2

// A check this tool performs did not pass
#define EXIT_CHECK 3

// print commands instead of running them
extern bool dry_run;

// used for progress indication
void step(const char *fmt, ...);

// error + cleanup + exit(1)
_Noreturn void die(const char *fmt, ...);

// if (cond) die(...) as one line. A macro, so the arguments stay unevaluated unless cond holds
#define die_if(cond, ...)     \
    do                        \
    {                         \
        if (cond)             \
            die(__VA_ARGS__); \
    } while (0)

// the running subcommand, for usage_err. main sets it before dispatch
extern const char *cmd_name;

// prints "c2vm <cmd>: ..." and returns EXIT_USAGE
int usage_err(const char *fmt, ...);

// same prefix as die, but the run carries on
void warn(const char *fmt, ...);

// formats into fresh storage the process never frees, convenient
const char *P(const char *fmt, ...);

// malloc/realloc/strdup that die instead of handing back NULL
void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

// reads whole file, caller frees
char *read_file(const char *path, size_t max);

// write a file using a format string
void write_file(const char *path, const char *fmt, ...);

// the last path component, or the whole string if there is no slash
const char *basename_of(const char *path);

// sorts array, removes duplicates, returns number of elements kept
size_t dedupe_sorted(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));

// locates an external tool. override if path is given by the user
const char *tool_path(const char *tool, const char *override);

char *base64_decode(const char *in, size_t *outlen);

#endif
