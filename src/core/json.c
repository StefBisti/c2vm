#include "core/json.h"
#include "core/util.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

const char *J(const char *s)
{
    char buf[PATH_MAX];

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
        if (w + n >= sizeof buf)
            die("cannot escape a value longer than %zu bytes", sizeof buf - 1);
        memcpy(buf + w, rep, n);
        w += n;
    }
    buf[w] = '\0';

    return xstrdup(buf);
}

char *json_get(const char *json, const char *key)
{
    char *k = strstr(json, P("\"%s\"", key));
    if (!k)
        return NULL;

    char *val = strchr(k + strlen(key) + 2, '"');
    if (!val)
        return NULL;

    char *end = (char *)json_skip_string(val) - 1;
    if (*end != '"')
        return NULL;

    size_t n = (size_t)(end - val - 1);
    char *out = xmalloc(n + 1);
    memcpy(out, val + 1, n);
    out[n] = '\0';

    return json_unescape(out);
}

char *json_get_in(const char *json, const char *section, const char *key)
{
    const char *from = strstr(json, P("\"%s\"", section));
    if (!from)
        return NULL;

    return json_get(from, key);
}

char *json_slurp(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        die("cannot stat %s: %s", path, strerror(errno));

    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot read %s: %s", path, strerror(errno));

    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf)
        die("out of memory reading %s (%lld bytes)", path, (long long)st.st_size);

    size_t got = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);

    buf[got] = '\0';
    return buf;
}

const char *json_skip_string(const char *p)
{
    p++;
    while (*p)
    {
        if (*p == '\\' && p[1])
            p += 2;
        else if (*p == '"')
            return p + 1;
        else
            p++;
    }
    return p;
}

// backet-matching extractor shared by json_array and json_object
static char *extract(const char *json, const char *key, char open_ch, char close_ch)
{
    const char *k = strstr(json, P("\"%s\"", key));
    if (!k)
        return NULL;

    const char *open = strchr(k + strlen(key) + 2, open_ch);
    if (!open)
        return NULL;

    int depth = 0;
    for (const char *p = open; *p; p++)
    {
        if (*p == '"')
        {
            p = json_skip_string(p) - 1;
            continue;
        }
        if (*p == open_ch)
            depth++;
        else if (*p == close_ch && --depth == 0)
        {
            size_t n = (size_t)(p - open) + 1;
            char *out = xmalloc(n + 1);
            memcpy(out, open, n);
            out[n] = '\0';
            return out;
        }
    }
    return NULL;
}

char *json_array(const char *json, const char *key)
{
    return extract(json, key, '[', ']');
}

char *json_object(const char *json, const char *key)
{
    return extract(json, key, '{', '}');
}

char *json_unescape(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++)
    {
        if (*r != '\\' || !r[1])
        {
            *w++ = *r;
            continue;
        }
        switch (*++r)
        {
        case 'n':
            *w++ = '\n';
            break;
        case 't':
            *w++ = '\t';
            break;
        case 'r':
            *w++ = '\r';
            break;
        case 'b':
            *w++ = '\b';
            break;
        case 'f':
            *w++ = '\f';
            break;
        case 'u': /* left as-is: nothing downstream reads non-ASCII fields */
            *w++ = '\\';
            *w++ = 'u';
            break;
        default:
            *w++ = *r;
        }
    }
    *w = '\0';
    return s;
}
