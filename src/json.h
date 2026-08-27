#ifndef C2VM_JSON_H
#define C2VM_JSON_H

const char *J(const char *s);
char *json_get(const char *json, const char *key);

/* Searched from the section key onward */
char *json_get_in(const char *json, const char *section, const char *key);

#endif
