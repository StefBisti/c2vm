#ifndef C2VM_RUN_H
#define C2VM_RUN_H

// first three take a NULL-terminated argument list: run("parted", "-s", disk, NULL)
// the other three, take an in-memory array of arguments

// returns exit status
int run(const char *prog, ...);

// dies if command fails
void run_ok(const char *prog, ...);

// returned stdout, caller frees
char *run_capture(const char *prog, ...);

// takes argument list, returns exit status
int run_argv(char *const argv[]);

// takes argument list, dies if command fails
void run_argv_ok(char *const argv[]);

// takes argument list, returns exit status, out = captured stdout
int run_argv_capture(char *const argv[], char **out);

#endif
