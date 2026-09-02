#ifndef C2VM_JSON_H
#define C2VM_JSON_H

const char *J(const char *s);
char *json_get(const char *json, const char *key);

/* Searched from the section key onward */
char *json_get_in(const char *json, const char *section, const char *key);

/* Whole file into one malloc'd, NUL-terminated buffer, sized by stat.
   For documents too big for read_file()'s up-front cap: SBOMs run to 8 MB
   and grype reports to 30. Dies on any read error. */
char *json_slurp(const char *path);

/* Given a pointer at a string's opening quote, returns the byte after its
   closing quote, honouring backslash escapes. A brace inside a description
   or a CPE must not move a caller's depth counter. */
const char *json_skip_string(const char *p);

#endif
