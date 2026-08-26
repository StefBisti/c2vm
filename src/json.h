#ifndef C2VM_JSON_H
#define C2VM_JSON_H

/* rotating pool, like P() */
const char *J(const char *s);

/* The first "key": "value" at or after the start of the buffer */
char *json_get(const char *json, const char *key);

/* The same, but searched from the section key onward, so that adding a key
   elsewhere in the document cannot silently redirect a lookup. */
char *json_get_in(const char *json, const char *section, const char *key);

#endif
