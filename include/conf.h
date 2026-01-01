#ifndef CONFIG_H
#define CONFIG_H

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* Path to the currently loaded configuration file (returns NULL if none) */
const char *get_loaded_config_path(void);

/* Other API */
char *normalize_path(const char *path);
static __attribute__((unused)) int is_port_available(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);

    if (rc == 0)
        return 1; // free
    if (errno == EADDRINUSE)
        return 0; // already used

    return -1; // other error (permission, etc)
}

#endif /* CONFIG_H */