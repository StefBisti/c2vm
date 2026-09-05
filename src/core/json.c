#include "core/json.h"
#include "core/run.h"
#include "core/util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Escapes a string for embedding in JSON. Allocates and leaks, for the same
   reason P() does: the result is usually one of a dozen arguments to a single
   fprintf, and a shared buffer cannot survive that. */
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
        if (w + n >= PATH_MAX)
            break; /* truncate rather than overflow */
        memcpy(buf + w, rep, n);
        w += n;
    }
    buf[w] = '\0';

    char *out = strdup(buf);
    if (!out)
        die("out of memory");
    return out;
}

/* The value of a string key. Escapes are left intact; json_unescape() them
   if the value is itself a document. */
char *json_get(const char *json, const char *key)
{
    char *k = strstr(json, P("\"%s\"", key));
    if (!k)
        return NULL;

    char *val = strchr(k + strlen(key) + 2, '"');
    if (!val)
        return NULL;

    /* Escape-aware: a value may contain \" - cosign's custom attestation
       stores a whole nested document as one such string. */
    char *end = (char *)json_skip_string(val) - 1;
    if (*end != '"')
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
    p++; /* opening quote */
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

/* Bracket-matching extractor shared by json_array and json_object. */
static char *extract(const char *doc, const char *key, char open_ch, char close_ch)
{
    const char *k = strstr(doc, P("\"%s\"", key));
    if (!k)
        return NULL;

    const char *open = strchr(k + strlen(key) + 2, open_ch);
    if (!open)
        return NULL;

    /* Depth, skipping strings: a value may contain a bracket, and stopping
       at the first one would truncate the result. */
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
            char *out = malloc(n + 1);
            if (!out)
                die("out of memory");
            memcpy(out, open, n);
            out[n] = '\0';
            return out;
        }
    }
    return NULL;
}

char *json_array(const char *doc, const char *key)
{
    return extract(doc, key, '[', ']');
}

char *json_object(const char *doc, const char *key)
{
    return extract(doc, key, '{', '}');
}

/* Decodes JSON string escapes in place. cosign's "custom" attestation type
   stores our whole statement as one escaped string under predicate.Data, so
   it has to be unescaped before it can be parsed as JSON again. */
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
        case 'n': *w++ = '\n'; break;
        case 't': *w++ = '\t'; break;
        case 'r': *w++ = '\r'; break;
        case 'b': *w++ = '\b'; break;
        case 'f': *w++ = '\f'; break;
        case 'u': /* left as-is: nothing downstream reads non-ASCII fields */
            *w++ = '\\';
            *w++ = 'u';
            break;
        default: *w++ = *r;
        }
    }
    *w = '\0';
    return s;
}
