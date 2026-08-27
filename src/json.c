#include "json.h"
#include "run.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NELEMS(a) (sizeof(a) / sizeof(a)[0])

// escapes strings with rotating buffers
const char *J(const char *s)
{
    static char pool[16][PATH_MAX];
    static size_t next;

    char *buf = pool[next];
    next = (next + 1) % NELEMS(pool);

    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++)
    {
        char esc[8];
        const char *rep = esc;

        switch (*p)
        {
        case '"':
            rep = "\\\"";
            break;
        case '\\':
            rep = "\\\\";
            break;
        case '\n':
            rep = "\\n";
            break;
        case '\r':
            rep = "\\r";
            break;
        case '\t':
            rep = "\\t";
            break;
        default:
            if (*p < 0x20)
                snprintf(esc, sizeof esc, "\\u%04x", *p);
            else
            {
                esc[0] = (char)*p;
                esc[1] = '\0';
            }
        }

        size_t n = strlen(rep);
        if (w + n >= PATH_MAX)
            break; /* truncate rather than overflow */
        memcpy(buf + w, rep, n);
        w += n;
    }
    buf[w] = '\0';

    return buf;
}

// only string values
char *json_get(const char *json, const char *key)
{
    char *k = strstr(json, P("\"%s\"", key));
    if (!k)
        return NULL;

    char *val = strchr(k + strlen(key) + 2, '"');
    if (!val)
        return NULL;

    char *end = strchr(val + 1, '"');
    if (!end)
        return NULL;

    size_t n = (size_t)(end - val - 1);
    char *out = malloc(n + 1);
    if (!out)
        die("out of memory");
    memcpy(out, val + 1, n);
    out[n] = '\0';

    return out;
}

char *json_get_in(const char *json, const char *section, const char *key)
{
    const char *from = strstr(json, P("\"%s\"", section));
    if (!from)
        return NULL;

    return json_get(from, key);
}
