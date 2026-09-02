#include "core/util.h"

#include <stdlib.h>
#include <string.h>

size_t dedupe_sorted(void *base, size_t n, size_t size,
                     int (*cmp)(const void *, const void *))
{
    if (n < 2)
        return n;

    qsort(base, n, size, cmp);

    char *a = base;
    size_t w = 1;

    /* w is the write cursor: keep an element only when it differs from the
       last one kept, so the survivors stay packed at the front. */
    for (size_t i = 1; i < n; i++)
        if (cmp(a + i * size, a + (w - 1) * size) != 0)
        {
            if (i != w)
                memcpy(a + w * size, a + i * size, size);
            w++;
        }

    return w;
}
