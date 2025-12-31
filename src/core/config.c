#include "conf.h"
#include "log.h"
#include "parser.h"
#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Global configuration instance */
ConfigCollection g_config = {0};

/* Forward declarations for internal functions */
static ConfigMap *get_or_create_section(const char *section);
static Config *get_or_create_entry(ConfigMap *map, const char *key);
static void config_entry_iterator(const char *section, const char *key, const char *value, void *ctx);
static char *resolve_absolute_path(const char *base_dir, const char *path);
static char *get_config_base_directory(void);
static bool is_absolute_path(const char *path);
static char *normalize_path(const char *path);

/* ====================== PUBLIC API ====================== */

ConfigCollection *get_global_config(void) {
    return &g_config;
}

int init_config(const char *config_path) {
    if (!config_path) {
        LOGE("Configuration path is NULL\n");
        return EXIT_FAILURE;
    }

    /* Store the config file directory for relative path resolution */
    char *config_dir = NULL;
    char *config_copy = strdup(config_path);
    if (config_copy) {
        config_dir = dirname(config_copy);
        char *base_dir = get_config_base_directory();
        if (base_dir) {
            free(base_dir);
        }
        /* Store the base directory in a global or static variable */
        g_config.base_directory = strdup(config_dir);
        free(config_copy);
    }

    LOGD("Using config file: %s (base dir: %s)\n", config_path, g_config.base_directory ? g_config.base_directory : "NULL");

    /* Verify file exists and is readable */
    struct stat st;
    if (stat(config_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        LOGE("Config file does not exist or is not a regular file: %s\n", config_path);
        return EXIT_FAILURE;
    }

    /* Parse configuration file */
    if (!parse_config_file(config_path, config_entry_iterator, NULL)) {
        LOGE("Failed to parse config file: %s\n", config_path);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void set_config_value(const char *section, const char *key, const char *value) {
    if (!section || !key || !value) {
        LOGE("set_config_value: NULL parameter detected (section: %p, key: %p, value: %p)\n",
             (void *)section, (void *)key, (void *)value);
        return;
    }

    ConfigMap *map = get_or_create_section(section);
    if (!map) {
        LOGE("Cannot create section '%s': maximum sections (%d) reached\n",
             section, MAX_SECTIONS);
        return;
    }

    Config *cfg = get_or_create_entry(map, key);
    if (!cfg) {
        LOGE("Cannot create entry '%s' in section '%s': maximum entries (%d) reached\n",
             key, section, MAX_CONF_MAP_ENTRIES);
        return;
    }

    /* Free previous value if it exists */
    if (cfg->value) {
        free(cfg->value);
        cfg->value = NULL;
    }

    /* Duplicate the new value */
    cfg->value = strdup(value);
    if (!cfg->value) {
        LOGE("Memory allocation failed for config value (section: %s, key: %s)\n",
             section, key);
    }
}

const char *get_config_value(const char *section, const char *key) {
    if (!section || !key) {
        LOGE("get_config_value: NULL parameter detected\n");
        return NULL;
    }

    ConfigCollection *cfg = get_global_config();

    for (size_t i = 0; i < cfg->section_count; i++) {
        if (strcmp(cfg->sections[i].section, section) == 0) {
            ConfigMap *map = &cfg->sections[i];

            for (size_t j = 0; j < map->entry_count; j++) {
                if (strcmp(map->entries[j].key, key) == 0) {
                    return map->entries[j].value;
                }
            }
            break; /* Section found but key not found */
        }
    }

    return NULL;
}

int get_config_int(const char *section, const char *key, int default_value) {
    const char *val = get_config_value(section, key);
    if (!val) {
        LOGD("Using default value %d for %s.%s\n", default_value, section, key);
        return default_value;
    }

    char *endptr;
    long result = strtol(val, &endptr, 10);

    /* Check for conversion errors */
    if (endptr == val || *endptr != '\0') {
        LOGW("Invalid integer value '%s' for %s.%s, using default %d\n", val, section, key, default_value);
        return default_value;
    }

    /* Check for overflow/underflow */
    if (result > INT_MAX || result < INT_MIN) {
        LOGW("Integer overflow for %s.%s: %ld, using default %d\n",
             section, key, result, default_value);
        return default_value;
    }

    return (int)result;
}

bool get_config_bool(const char *section, const char *key, bool default_value) {
    const char *val = get_config_value(section, key);
    if (!val) {
        LOGD("Using default value %s for %s.%s\n",
             default_value ? "true" : "false", section, key);
        return default_value;
    }

    /* Check for truthy values */
    if (strcmp(val, "1") == 0 ||
        strcasecmp(val, "true") == 0 ||
        strcasecmp(val, "yes") == 0 ||
        strcasecmp(val, "on") == 0 ||
        strcasecmp(val, "enabled") == 0) {
        return true;
    }

    /* Check for falsy values */
    if (strcmp(val, "0") == 0 ||
        strcasecmp(val, "false") == 0 ||
        strcasecmp(val, "no") == 0 ||
        strcasecmp(val, "off") == 0 ||
        strcasecmp(val, "disabled") == 0) {
        return false;
    }

    LOGW("Invalid boolean value '%s' for %s.%s, using default %s\n",
         val, section, key, default_value ? "true" : "false");
    return default_value;
}

char *get_config_path(const char *section, const char *key, const char *default_path) {
    const char *val = get_config_value(section, key);
    if (!val) {
        if (default_path) {
            LOGD("Using default path '%s' for %s.%s\n", default_path, section, key);
            return resolve_config_path(default_path);
        }
        return NULL;
    }

    return resolve_config_path(val);
}

char *resolve_config_path(const char *path) {
    if (!path) {
        return NULL;
    }

    /* If it's already an absolute path, just normalize it */
    if (is_absolute_path(path)) {
        return normalize_path(path);
    }

    /* Try to resolve relative to config file directory first */
    if (g_config.base_directory) {
        char *resolved = resolve_absolute_path(g_config.base_directory, path);
        if (resolved) {
            struct stat st;
            if (stat(resolved, &st) == 0) {
                LOGD("Resolved path '%s' -> '%s' (relative to config)\n", path, resolved);
                return resolved;
            }
            free(resolved);
        }
    }

    /* Try to resolve relative to current working directory */
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        char *resolved = resolve_absolute_path(cwd, path);
        if (resolved) {
            struct stat st;
            if (stat(resolved, &st) == 0) {
                LOGD("Resolved path '%s' -> '%s' (relative to CWD)\n", path, resolved);
                return resolved;
            }
            free(resolved);
        }
    }

    /* Last resort: just normalize the path as-is */
    LOGD("Could not resolve path '%s', returning normalized version\n", path);
    return normalize_path(path);
}

char *get_config_path_with_default(const char *section, const char *key, const char *default_path, bool must_exist) {
    char *path = get_config_path(section, key, default_path);
    if (!path) {
        return NULL;
    }

    if (must_exist) {
        struct stat st;
        if (stat(path, &st) != 0) {
            LOGW("Path does not exist: %s\n", path);
            free(path);
            return NULL;
        }
    }

    return path;
}

void get_config_section(const char *section, config_section_callback_t callback, void *ctx) {
    if (!section || !callback) {
        LOGE("get_config_section: NULL parameter detected\n");
        return;
    }

    ConfigCollection *cfg = get_global_config();

    for (size_t i = 0; i < cfg->section_count; i++) {
        if (strcmp(cfg->sections[i].section, section) == 0) {
            ConfigMap *map = &cfg->sections[i];

            for (size_t j = 0; j < map->entry_count; j++) {
                callback(map->entries[j].key, map->entries[j].value, ctx);
            }
            return;
        }
    }

    LOGD("Section '%s' not found\n", section);
}

void iterate_config_sections(config_section_iterator_t iterator, void *ctx) {
    if (!iterator) {
        LOGE("iterate_config_sections: NULL iterator\n");
        return;
    }

    ConfigCollection *cfg = get_global_config();

    for (size_t i = 0; i < cfg->section_count; i++) {
        ConfigMap *map = &cfg->sections[i];

        /* Call the iterator for each section */
        iterator(map->section, map->entry_count, ctx);
    }
}

void free_config(void) {
    for (size_t i = 0; i < g_config.section_count; i++) {
        ConfigMap *map = &g_config.sections[i];

        for (size_t j = 0; j < map->entry_count; j++) {
            free(map->entries[j].key);
            free(map->entries[j].value);
            map->entries[j].key = NULL;
            map->entries[j].value = NULL;
        }

        free(map->section);
        map->section = NULL;
        map->entry_count = 0;
    }

    if (g_config.base_directory) {
        free(g_config.base_directory);
        g_config.base_directory = NULL;
    }

    g_config.section_count = 0;
}

/* ====================== INTERNAL FUNCTIONS ====================== */

static void config_entry_iterator(const char *section, const char *key, const char *value, void *ctx) {
    (void)ctx; /* Unused parameter */
    set_config_value(section, key, value);
}

static ConfigMap *get_or_create_section(const char *section) {
    if (!section) {
        return NULL;
    }

    /* Search for existing section */
    for (size_t i = 0; i < g_config.section_count; i++) {
        if (strcmp(g_config.sections[i].section, section) == 0) {
            return &g_config.sections[i];
        }
    }

    /* Check if we can create a new section */
    if (g_config.section_count >= MAX_SECTIONS) {
        return NULL;
    }

    /* Create new section */
    ConfigMap *new_section = &g_config.sections[g_config.section_count++];
    new_section->section = strdup(section);

    if (!new_section->section) {
        LOGE("Memory allocation failed for section name: %s\n", section);
        g_config.section_count--; /* Rollback */
        return NULL;
    }

    new_section->entry_count = 0;
    return new_section;
}

static Config *get_or_create_entry(ConfigMap *map, const char *key) {
    if (!map || !key) {
        return NULL;
    }

    /* Search for existing entry */
    for (size_t i = 0; i < map->entry_count; i++) {
        if (strcmp(map->entries[i].key, key) == 0) {
            return &map->entries[i];
        }
    }

    /* Check if we can create a new entry */
    if (map->entry_count >= MAX_CONF_MAP_ENTRIES) {
        return NULL;
    }

    /* Create new entry */
    Config *cfg = &map->entries[map->entry_count++];
    cfg->key = strdup(key);

    if (!cfg->key) {
        LOGE("Memory allocation failed for key: %s\n", key);
        map->entry_count--; /* Rollback */
        return NULL;
    }

    cfg->value = NULL;
    return cfg;
}

static bool is_absolute_path(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    /* Check for Unix absolute path */
    if (path[0] == '/') {
        return true;
    }

    /* Check for Windows absolute path (optional) */
#ifdef _WIN32
    if (strlen(path) >= 3 &&
        ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) &&
        path[1] == ':' && (path[2] == '/' || path[2] == '\\')) {
        return true;
    }
#endif

    return false;
}

static char *resolve_absolute_path(const char *base_dir, const char *path) {
    if (!base_dir || !path) {
        return NULL;
    }

    size_t base_len = strlen(base_dir);
    size_t path_len = strlen(path);

    /* Allocate memory for combined path + separator + null terminator */
    char *combined = malloc(base_len + path_len + 2); /* +2 for '/' and null */
    if (!combined) {
        LOGE("Memory allocation failed for path resolution\n");
        return NULL;
    }

    /* Copy base directory */
    strcpy(combined, base_dir);

    /* Add separator if needed */
    if (base_len > 0 && base_dir[base_len - 1] != '/' && path[0] != '/') {
        strcat(combined, "/");
    }

    /* Append the relative path */
    strcat(combined, path);

    /* Normalize the combined path */
    char *normalized = normalize_path(combined);
    free(combined);

    return normalized;
}

static char *normalize_path(const char *path) {
    if (!path) {
        return NULL;
    }

    char *copy = strdup(path);
    if (!copy) {
        return NULL;
    }

    /* Remove trailing slashes (except for root) */
    size_t len = strlen(copy);
    while (len > 1 && copy[len - 1] == '/') {
        copy[--len] = '\0';
    }

    /* Handle ".." and "." components */
    char *result = realpath(copy, NULL);
    if (!result) {
        /* realpath failed, return the cleaned copy */
        return copy;
    }

    free(copy);
    return result;
}

static char *get_config_base_directory(void) {
    /* This function is called during init_config to store the base directory */
    return g_config.base_directory;
}