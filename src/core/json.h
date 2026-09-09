#ifndef C2VM_JSON_H
#define C2VM_JSON_H

// escapes a string in order to embed it into json
const char *J(const char *s);

// gets a field's value, unescaped
char *json_get(const char *json, const char *key);

// gets a field's value from section onwards
char *json_get_in(const char *json, const char *section, const char *key);

// reads a json file with malloc
char *json_slurp(const char *path);

// moves the pointer p from the start of the quote to the end
const char *json_skip_string(const char *p);

// gets raw json array, brackets included
char *json_array(const char *json, const char *key);

// gets raw json object, curly braces included
char *json_object(const char *json, const char *key);

// undoes json string escapes
char *json_unescape(char *s);

#endif
