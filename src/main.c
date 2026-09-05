#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/util.h"
#include "convert/boottest.h"
#include "convert/build.h"
#include "custody/scan.h"
#include "custody/diff.h"
#include "custody/cve.h"
#include "custody/publish.h"
#include "custody/verify.h"

#define EXIT_USAGE_ERROR EXIT_USAGE

typedef int (*handler_fn)(int argc, char *argv[]);

struct command
{
    const char *name;
    handler_fn handler;
};

static const struct command COMMANDS[] = {
    {"build", cmd_build},
    {"boot-test", cmd_boot_test},
    {"scan", cmd_scan},
    {"diff", cmd_diff},
    {"cve", cmd_cve},
    {"push", cmd_push},
    {"sign", cmd_sign},
    {"attest", cmd_attest},
    {"verify", cmd_verify},
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
        "                          --user <name>          default user (default: c2vm)\n"
        "                          --root-password <file> opt-in root password (hashed)\n"

        "\n"
        "  boot-test <artifact>  Boot the artifact headless and assert the guest came up\n"
        "                          --ssh-key <path>       private key to log in with\n"
        "                          --user <name>          guest account (default: c2vm)\n"
        "                          --timeout <sec>        hard limit (default: 180)\n"
        "\n"
        "  scan <artifact>       Generate an SBOM of a built disk and scan it for CVEs\n"
        "  diff <sbom-a> <sbom-b>\n"
        "                        Report the package delta between two SBOMs\n"
        "  cve <report-a> <report-b>\n"
        "                        Report the vulnerability delta between two grype reports\n"
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
        "            3 verification or policy failure\n"
        "\n",
        out);
}

static const struct command *lookup(const char *name)
{
    for (size_t i = 0; i < CMD_COUNT; i++)
        if (strcmp(COMMANDS[i].name, name) == 0)
            return &COMMANDS[i];
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage(stdout);
        return EXIT_SUCCESS;
    }

    const char *cmd = argv[1];

    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help"))
    {
        usage(stdout);
        return EXIT_SUCCESS;
    }

    if (!strcmp(cmd, "--version"))
    {
        puts("c2vm " C2VM_VERSION);
        return EXIT_SUCCESS;
    }

    const struct command *c = lookup(cmd);
    if (!c)
    {
        fprintf(stderr, "c2vm: unknown command '%s'\n", cmd);
        fprintf(stderr, "try: c2vm --help\n");
        return EXIT_USAGE_ERROR;
    }

    return c->handler(argc - 2, argv + 2);
}
