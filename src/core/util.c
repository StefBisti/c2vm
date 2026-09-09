#include "core/util.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool dry_run = false;

void step(const char *fmt, ...)
{
    fputs("\n==> ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void die(const char *fmt, ...)
{
    fputs("c2vm: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

const char *P(const char *fmt, ...)
{
    char buf[PATH_MAX];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    char *s = strdup(buf);
    if (!s)
        die("out of memory");
    return s;
}

char *read_file(const char *path, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f)
        die("cannot read %s: %s", path, strerror(errno));

    char *buf = malloc(max + 1);
    if (!buf)
        die("out of memory");

    size_t n = fread(buf, 1, max, f);
    bool overflow = fgetc(f) != EOF;
    fclose(f);

    if (overflow)
    {
        free(buf);
        die("%s is larger than %zu bytes", path, max);
    }
    buf[n] = '\0';

    if (strlen(buf) != n)
    {
        free(buf);
        die("%s contains a NUL byte", path);
    }

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        buf[--n] = '\0';

    return buf;
}

void write_file(const char *path, const char *fmt, ...)
{
    fprintf(stderr, dry_run ? "  would write: %s\n" : "  > %s\n", path);
    if (dry_run)
        return;

    FILE *f = fopen(path, "w");
    if (!f)
        die("cannot write %s: %s", path, strerror(errno));

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

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

const char *tool_path(const char *tool, const char *override)
{
    if (override)
        return override;

    char found[PATH_MAX];

    static const char *DIRS[] = {"/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"};

    for (size_t i = 0; i < NELEMS(DIRS); i++)
    {
        snprintf(found, sizeof found, "%s/%s", DIRS[i], tool);
        if (access(found, X_OK) == 0)
            return P("%s", found);
    }

    const char *user = getenv("SUDO_USER");
    if (user)
    {
        snprintf(found, sizeof found, "/home/%s/.local/bin/%s", user, tool);
        if (access(found, X_OK) == 0)
            return P("%s", found);
    }

    const char *home = getenv("HOME");
    if (home)
    {
        snprintf(found, sizeof found, "%s/.local/bin/%s", home, tool);
        if (access(found, X_OK) == 0)
            return P("%s", found);
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
            continue; // padding, newlines, whitespace
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
