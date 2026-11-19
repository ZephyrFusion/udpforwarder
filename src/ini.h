/* Minimal ini parser: supports [section], key = value, and # / ; comments. */
#ifndef UFW_INI_H
#define UFW_INI_H

#include <stddef.h>

typedef struct ini ini_t;

/* Returns NULL on failure and writes the reason into err. */
ini_t *ini_load(const char *path, char *err, size_t errlen);
void ini_free(ini_t *ini);

/* Returns NULL if not found (section and key names are case-insensitive). */
const char *ini_get(const ini_t *ini, const char *section, const char *key);

/* Falls back to def when absent; parses an integer and requires it to be within
 * [min, max], otherwise returns -1. */
int ini_get_uint(const ini_t *ini, const char *section, const char *key,
                 unsigned long def, unsigned long min, unsigned long max,
                 unsigned long *out);

#endif /* UFW_INI_H */
