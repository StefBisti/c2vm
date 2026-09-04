#include "core/util.h"

#include "core/run.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

size_t dedupe_sorted(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *))
{
    if (n < 2)
        return n;

    qsort(base, n, size, cmp);

    char *a = base;
    size_t w = 1;

    for (size_t i = 1; i < n; i++)
        if (cmp(a + i * size, a + (w - 1) * size) != 0)
        {
            if (i != w)
                memcpy(a + w * size, a + i * size, size);
            w++;
        }

    return w;
}

#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

const char *tool_path(const char *tool, const char *override, char *found, size_t cap)
{
    if (override)
        return override;

    static const char *DIRS[] = {"/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"};

    for (size_t i = 0; i < NELEMS(DIRS); i++)
    {
        snprintf(found, cap, "%s/%s", DIRS[i], tool);
        if (access(found, X_OK) == 0)
            return found;
    }

    const char *user = getenv("SUDO_USER");
    if (user)
    {
        snprintf(found, cap, "/home/%s/.local/bin/%s", user, tool);
        if (access(found, X_OK) == 0)
            return found;
    }

    const char *home = getenv("HOME");
    if (home)
    {
        snprintf(found, cap, "%s/.local/bin/%s", home, tool);
        if (access(found, X_OK) == 0)
            return found;
    }

    die("cannot find %s; install it or pass --%s <path>", tool, tool);
    return NULL;
}

static int b64val(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

char *base64_decode(const char *in, size_t *outlen)
{
    size_t n = strlen(in);
    char *out = malloc(n / 4 * 3 + 4);
    if (!out)
        die("out of memory");

    unsigned acc = 0;
    int bits = 0;
    size_t w = 0;

    for (const char *p = in; *p; p++)
    {
        int v = b64val((unsigned char)*p);
        if (v < 0)
            continue; /* padding, newlines, whitespace */
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out[w++] = (char)((acc >> bits) & 0xff);
        }
    }

    out[w] = '\0';
    if (outlen)
        *outlen = w;
    return out;
}
