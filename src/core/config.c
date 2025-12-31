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

static char *resolve_config_path(const char *path);

/* Global configuration instance */
static ConfigCollection cfg = {0};
static char config_file_path[PATH_MAX] = "";

/* ====================== INTERNAL FUNCTIONS ====================== */
static config_callback_t config_entry_iterator(const char *section, const char *key, const char *value, void *ctx) {
    (void)ctx; /* Unused parameter */
    set_config_value(section, key, value);
}

static ConfigMap *get_or_create_section(const char *section) {
    if (!section) {
        return NULL;
    }

    /* Search for existing section */
    for (size_t i = 0; i < cfg.section_count; i++) {
        if (strcmp(cfg.sections[i].section, section) == 0) {
            return &cfg.sections[i];
        }
    }

    /* Check if we can create a new section */
    if (cfg.section_count >= MAX_SECTIONS) {
        return NULL;
    }

    /* Create new section */
    ConfigMap *new_section = &cfg.sections[cfg.section_count++];
    new_section->section = strdup(section);

    if (!new_section->section) {
        LOGE("Memory allocation failed for section name: %s\n", section);
        cfg.section_count--; /* Rollback */
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

/* ====================== PUBLIC API ====================== */

ConfigCollection *get_global_config(void) {
    return &cfg;
}

int init_config(const char *config_path) {
    if (!config_path) {
        LOGE("Configuration path is NULL\n");
        return EXIT_FAILURE;
    }

    LOGD("Loading config file: %s\n", config_path);

    // Normalize the config file path
    char *normalized_path = normalize_path(config_path);
    if (!normalized_path) {
        LOGE("Failed to normalize config path: %s\n", config_path);
        return EXIT_FAILURE;
    }

    LOGD("Normalized config path: %s\n", normalized_path);

    // Verify file exists and is readable
    struct stat st;
    if (stat(normalized_path, &st) != 0) {
        LOGE("Config file does not exist: %s\n", normalized_path);
        free(normalized_path);
        return EXIT_FAILURE;
    }

    if (!S_ISREG(st.st_mode)) {
        LOGE("Config path is not a regular file: %s\n", normalized_path);
        free(normalized_path);
        return EXIT_FAILURE;
    }

    if (access(normalized_path, R_OK) != 0) {
        LOGE("Config file is not readable: %s\n", normalized_path);
        free(normalized_path);
        return EXIT_FAILURE;
    }

    LOGD("Config file exists and is readable, starting parse...\n");

    printf("Using configuration file: %s\n", normalized_path);
    /* Parse configuration file */
    if (parse_config_file(normalized_path, config_entry_iterator, &cfg) == EXIT_FAILURE) {
        LOGE("Failed to parse config file: %s\n", normalized_path);
        LOGE("Check for syntax errors in the config file\n");
        free(normalized_path);
        return EXIT_FAILURE;
    }

    LOGD("Config file parsed successfully\n");

    /* Apply logging configuration immediately */
    log_reload_config();

    // Keep a copy of the normalized path so reloads can use it
    strncpy(config_file_path, normalized_path, sizeof(config_file_path)-1);
    config_file_path[sizeof(config_file_path)-1] = '\0';

    // Clean up
    free(normalized_path);

    // Debug: print loaded sections
    LOGD("Loaded %zu configuration sections\n", cfg.section_count);
    for (size_t i = 0; i < cfg.section_count; i++) {
        LOGD("  Section [%s] has %zu entries\n",cfg.sections[i].section, cfg.sections[i].entry_count);
    }

    return EXIT_SUCCESS;
}

const char *get_loaded_config_path(void) {
    if (config_file_path[0] == '\0') return NULL;
    return config_file_path;
}

void set_config_value(const char *section, const char *key, const char *value) {
    if (!section || !key || !value) {
        LOGE("set_config_value: NULL parameter detected (section: %p, key: %p, value: %p)\n",
             (void *)section, (void *)key, (void *)value);
        return;
    }

    LOGD("Setting config: [%s] %s = %s\n", section, key, value);

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

    LOGD("Config value not found: [%s] %s\n", section, key);
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

char *normalize_path(const char *path) {
    if (!path)
        return NULL;

    // Handle absolute paths
    if (path[0] == '/') {
        char *resolved = realpath(path, NULL);
        if (resolved) {
            return resolved;
        }
        // If realpath fails, return the path as-is
        return strdup(path);
    }

    // Handle relative paths
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return NULL;
    }

    // Construct full path
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", cwd, path);

    // Resolve symlinks and normalize
    char *resolved = realpath(full_path, NULL);
    if (resolved) {
        return resolved;
    }

    // If realpath fails (file might not exist), return the constructed path
    return strdup(full_path);
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

static char *resolve_config_path(const char *path) {
    if (!path) {
        return NULL;
    }

    // If it's an absolute path
    if (path[0] == '/') {
        return normalize_path(path);
    }

    // Try as-is
    char *resolved = normalize_path(path);
    if (resolved) {
        LOGD("Resolved '%s' -> '%s' (normalized)\n", path, resolved);
        return resolved;
    }

    return NULL;
}

void free_config(void) {
    for (size_t i = 0; i < cfg.section_count; i++) {
        ConfigMap *map = &cfg.sections[i];

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

    cfg.section_count = 0;
}