#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_SECTIONS 100
#define MAX_CONF_MAP_ENTRIES 500

/* Configuration structures */
typedef struct {
    char *key;
    char *value;
} Config;

typedef struct {
    char *section;
    Config entries[MAX_CONF_MAP_ENTRIES];
    size_t entry_count;
} ConfigMap;

typedef struct {
    ConfigMap sections[MAX_SECTIONS];
    size_t section_count;
    char *base_directory; /* Added for path resolution */
} ConfigCollection;

/* Callback types */
typedef void (*config_section_callback_t)(const char *key, const char *value, void *ctx);
typedef void (*config_section_iterator_t)(const char *section, size_t entry_count, void *ctx);

/* Core API */
ConfigCollection *get_global_config(void);
int init_config(const char *config_path);
void set_config_value(const char *section, const char *key, const char *value);
const char *get_config_value(const char *section, const char *key);
int get_config_int(const char *section, const char *key, int default_value);
bool get_config_bool(const char *section, const char *key, bool default_value);
void get_config_section(const char *section, config_section_callback_t callback, void *ctx);
void iterate_config_sections(config_section_iterator_t iterator, void *ctx);
void free_config(void);

/* Path resolution API */
char *get_config_path(const char *section, const char *key, const char *default_path);
char *get_config_path_with_default(const char *section, const char *key,
                                   const char *default_path, bool must_exist);
char *resolve_config_path(const char *path);

#endif /* CONFIG_H */