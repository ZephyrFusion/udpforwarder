#include "ini.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INI_MAX_ENTRIES 256
#define INI_NAME_LEN 64
#define INI_VALUE_LEN 256
#define INI_LINE_LEN 1024

struct ini_entry {
    char section[INI_NAME_LEN];
    char key[INI_NAME_LEN];
    char value[INI_VALUE_LEN];
};

struct ini {
    struct ini_entry entries[INI_MAX_ENTRIES];
    size_t count;
};

static char *trim(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

static void strip_comment(char *s)
{
    /* 只处理整行注释；行内以 " #" / " ;" 开始的部分也当作注释 */
    for (char *p = s; *p; p++) {
        if ((*p == '#' || *p == ';') && (p == s || isspace((unsigned char)p[-1]))) {
            *p = '\0';
            return;
        }
    }
}

static void strip_quotes(char *s)
{
    size_t len = strlen(s);

    if (len < 2)
        return;
    if ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\'')) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

ini_t *ini_load(const char *path, char *err, size_t errlen)
{
    FILE *fp;
    struct ini *ini;
    char line[INI_LINE_LEN];
    char section[INI_NAME_LEN] = "";
    unsigned long lineno = 0;

    fp = fopen(path, "r");
    if (!fp) {
        snprintf(err, errlen, "无法打开配置文件 %s: %s", path, strerror(errno));
        return NULL;
    }

    ini = calloc(1, sizeof(*ini));
    if (!ini) {
        snprintf(err, errlen, "内存不足");
        fclose(fp);
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *s;
        char *eq;

        lineno++;
        if (!strchr(line, '\n') && !feof(fp)) {
            snprintf(err, errlen, "%s:%lu: 行太长", path, lineno);
            goto fail;
        }
        strip_comment(line);
        s = trim(line);
        if (*s == '\0')
            continue;

        if (*s == '[') {
            char *rb = strchr(s, ']');
            if (!rb) {
                snprintf(err, errlen, "%s:%lu: 段名缺少 ']'", path, lineno);
                goto fail;
            }
            *rb = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            continue;
        }

        eq = strchr(s, '=');
        if (!eq) {
            snprintf(err, errlen, "%s:%lu: 缺少 '='", path, lineno);
            goto fail;
        }
        *eq = '\0';
        {
            char *key = trim(s);
            char *val = trim(eq + 1);

            strip_quotes(val);
            if (*key == '\0') {
                snprintf(err, errlen, "%s:%lu: 键名为空", path, lineno);
                goto fail;
            }
            if (ini->count >= INI_MAX_ENTRIES) {
                snprintf(err, errlen, "%s:%lu: 条目太多（上限 %d）", path, lineno,
                         INI_MAX_ENTRIES);
                goto fail;
            }
            snprintf(ini->entries[ini->count].section, INI_NAME_LEN, "%s", section);
            snprintf(ini->entries[ini->count].key, INI_NAME_LEN, "%s", key);
            snprintf(ini->entries[ini->count].value, INI_VALUE_LEN, "%s", val);
            ini->count++;
        }
    }

    fclose(fp);
    return ini;

fail:
    fclose(fp);
    ini_free(ini);
    return NULL;
}

void ini_free(ini_t *ini)
{
    free(ini);
}

const char *ini_get(const ini_t *ini, const char *section, const char *key)
{
    if (!ini)
        return NULL;
    for (size_t i = 0; i < ini->count; i++) {
        if (strcasecmp(ini->entries[i].section, section) == 0 &&
            strcasecmp(ini->entries[i].key, key) == 0)
            return ini->entries[i].value;
    }
    return NULL;
}

int ini_get_uint(const ini_t *ini, const char *section, const char *key,
                 unsigned long def, unsigned long min, unsigned long max,
                 unsigned long *out)
{
    const char *val = ini_get(ini, section, key);
    char *end = NULL;
    unsigned long v;

    if (!val) {
        if (def < min || def > max)
            return -1;
        *out = def;
        return 0;
    }

    errno = 0;
    v = strtoul(val, &end, 0);
    if (errno != 0 || end == val || *end != '\0' || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}
