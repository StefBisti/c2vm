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
