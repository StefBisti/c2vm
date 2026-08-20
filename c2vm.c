#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./src/build.h"


#define C2VM_VERSION "0.0.1-dev"
#define EXIT_RUNTIME_FAILURE_ERROR 1
#define EXIT_USAGE_ERROR 2
#define EXIT_NOT_IMPLEMENTED_ERROR 64

typedef int (*handler_fn)(int argc, char *argv[]);

static int cmd_scan(int argc, char *argv[]);
static int cmd_diff(int argc, char *argv[]);
static int cmd_push(int argc, char *argv[]);
static int cmd_sign(int argc, char *argv[]);
static int cmd_attest(int argc, char *argv[]);
static int cmd_verify(int argc, char *argv[]);

struct command {
    const char *name;
    handler_fn handler;
};

static const struct command COMMANDS[] = {
    { "build",  cmd_build  },
    { "scan",   cmd_scan   },
    { "diff",   cmd_diff   },
    { "push",   cmd_push   },
    { "sign",   cmd_sign   },
    { "attest", cmd_attest },
    { "verify", cmd_verify },
};

static const size_t CMD_COUNT = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

static void usage(FILE *out)
{
    fputs(
        "c2vm — convert a container image into a bootable VM disk, with provenance.\n"
        "\n"
        "usage: c2vm <command> [options]\n"
        "\n"
        "commands:\n"
        "  build <image-ref>     Build a bootable disk from a container image\n"
        "                          --format qcow2,ova     output formats (default: qcow2)\n"
        "                          --size 10G             disk size\n"
        "                          --ssh-key <path>       authorized key for the default user\n"
        "                          --packages <list>      extra packages, comma-separated\n"
        "\n"
        "  scan <artifact>       Generate an SBOM of a built disk and scan it for CVEs\n"
        "  diff <sbom-a> <sbom-b>\n"
        "                        Report the package delta between two SBOMs\n"
        "  push <artifact> <oci-ref>\n"
        "                        Publish the artefact to an OCI registry\n"
        "  sign <oci-ref>        Sign the published artefact (keyless)\n"
        "  attest <oci-ref>      Attach the SBOM and conversion attestations\n"
        "  verify <oci-ref>      Verify signature, attestations and policy\n"
        "                          --policy policy/default.yaml\n"
        "\n"
        "global:\n"
        "  -h, --help            Show this help\n"
        "      --version         Show the version\n"
        "\n"
        "exit codes: 0 ok · 1 runtime failure · 2 usage error\n"
        "            3 verification or policy failure · 64 not implemented\n"
        "\n",
        out);
}

static int not_implemented(const char *name)
{
    fprintf(stderr, "c2vm: '%s' is not implemented yet\n", name);
    return EXIT_NOT_IMPLEMENTED_ERROR;
}

static int cmd_scan(int argc, char *argv[])   { (void)argc; (void)argv; return not_implemented("scan"); }
static int cmd_diff(int argc, char *argv[])   { (void)argc; (void)argv; return not_implemented("diff"); }
static int cmd_push(int argc, char *argv[])   { (void)argc; (void)argv; return not_implemented("push"); }
static int cmd_sign(int argc, char *argv[])   { (void)argc; (void)argv; return not_implemented("sign"); }
static int cmd_attest(int argc, char *argv[]) { (void)argc; (void)argv; return not_implemented("attest"); }
static int cmd_verify(int argc, char *argv[]) { (void)argc; (void)argv; return not_implemented("verify"); }

static const struct command *lookup(const char *name)
{
    for (size_t i = 0; i < CMD_COUNT; i++)
        if (strcmp(COMMANDS[i].name, name) == 0)
            return &COMMANDS[i];
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(stdout);
        return EXIT_SUCCESS;
    }

    const char *cmd = argv[1];

    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
        usage(stdout);
        return EXIT_SUCCESS;
    }

    if (!strcmp(cmd, "--version")) {
        puts("c2vm " C2VM_VERSION);
        return EXIT_SUCCESS;
    }

    const struct command *c = lookup(cmd);
    if (!c) {
        fprintf(stderr, "c2vm: unknown command '%s'\n", cmd);
        fprintf(stderr, "try: c2vm --help\n");
        return EXIT_USAGE_ERROR;
    }

    return c->handler(argc - 2, argv + 2);
}
