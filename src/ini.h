/* 极简 ini 配置解析器：支持 [section]、key = value、# 和 ; 注释 */
#ifndef UFW_INI_H
#define UFW_INI_H

#include <stddef.h>

typedef struct ini ini_t;

/* 失败返回 NULL，err 里写入原因 */
ini_t *ini_load(const char *path, char *err, size_t errlen);
void ini_free(ini_t *ini);

/* 找不到返回 NULL（键名/段名大小写不敏感） */
const char *ini_get(const ini_t *ini, const char *section, const char *key);

/* 缺省时用 def；解析成整数并且要求在 [min, max] 内，否则返回 -1 */
int ini_get_uint(const ini_t *ini, const char *section, const char *key,
                 unsigned long def, unsigned long min, unsigned long max,
                 unsigned long *out);

#endif /* UFW_INI_H */
