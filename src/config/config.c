#include "conf.h"
#include "log.h"
#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>

ServerConfig g_config;
const ServerConfig *get_config(void) {
    return &g_config;
}

// Get executable path
static void get_exe_path(char *buf, size_t size) {
#ifdef __linux__
    ssize_t len = readlink("/proc/self/exe", buf, size - 1);
    if (len != -1) {
        buf[len] = '\0';
    } else {
        strncpy(buf, ".", size);
    }
#elif defined(__APPLE__)
    uint32_t size_u = (uint32_t)size;
    if (_NSGetExecutablePath(buf, &size_u) == 0) {
        // Success
    } else {
        strncpy(buf, ".", size);
    }
#else
    strncpy(buf, ".", size);
#endif
}




// Get executable directory
static void get_exe_dir(char *buf, size_t size) {
    char exe_path[PATH_MAX];
    get_exe_path(exe_path, sizeof(exe_path));

    char *dir = dirname(exe_path);
    strncpy(buf, dir, size - 1);
    buf[size - 1] = '\0';
}




// Find configuration file in search paths
static char *find_config_file(const char *custom_path) {
    static char config_path[PATH_MAX];

    // 1. Use custom path if provided
    if (custom_path && custom_path[0]) {
        if (access(custom_path, R_OK) == 0) {
            strncpy(config_path, custom_path, sizeof(config_path) - 1);
            return config_path;
        }
    }

    // 2. Check current directory
    if (access("lightmail.conf", R_OK) == 0) {
        strncpy(config_path, "lightmail.conf", sizeof(config_path) - 1);
        return config_path;
    }

    // 3. Check in executable directory
    char exe_dir[PATH_MAX];
    get_exe_dir(exe_dir, sizeof(exe_dir));
    snprintf(config_path, sizeof(config_path), "%s/lightmail.conf", exe_dir);
    if (access(config_path, R_OK) == 0) {
        return config_path;
    }

    // 4. Check in executable directory + ../config/
    snprintf(config_path, sizeof(config_path), "%s/../config/lightmail.conf", exe_dir);
    if (access(config_path, R_OK) == 0) {
        return config_path;
    }

    // 5. Check system configuration directories
    const char *system_paths[] = {
        "/etc/lightmail/lightmail.conf",
        "/usr/local/etc/lightmail/lightmail.conf",
        "/opt/lightmail/etc/lightmail.conf",
        NULL};

    for (int i = 0; system_paths[i]; i++) {
        if (access(system_paths[i], R_OK) == 0) {
            strncpy(config_path, system_paths[i], sizeof(config_path) - 1);
            return config_path;
        }
    }

    // 6. Fallback to compiled-in default
    strncpy(config_path, "/etc/lightmail/lightmail.conf", sizeof(config_path) - 1);
    return config_path;
}






// Trim whitespace from string
static void trim(char *str) {
    if (!str)
        return;

    bool in_quotes = false;
    char *ptr = str;
    char *comment_pos = NULL;

    // 1. Identify the true comment (only if outside quotes)
    while (*ptr) {
        if (*ptr == '"') {
            in_quotes = !in_quotes; // Toggle state
        } else if (*ptr == '#' && !in_quotes) {
            comment_pos = ptr;
            break; // Found a real comment
        }
        ptr++;
    }

    // Terminate at the comment if found
    if (comment_pos)
        *comment_pos = '\0';

    // 2. Find start (skip leading whitespace)
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    // 3. Find end (skip trailing whitespace)
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';

    // 4. Remove surrounding quotes IF they exist
    if (*start == '"' && *end == '"' && end > start) {
        start++;     // Move past first quote
        *end = '\0'; // Overwrite last quote
    }

    // 5. Shift back to original pointer
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}






// Expand path variables
static void expand_path(char *dest, size_t dest_size, const char *src) {
    char result[PATH_MAX];
    const char *ptr = src;
    char *out = result;

    while (*ptr && (out - result) < (PATH_MAX - 1)) {
        if (*ptr == '$' && *(ptr + 1) == '{') {
            const char *var_start = ptr + 2;
            const char *var_end = strchr(var_start, '}');

            if (var_end) {
                int var_len = var_end - var_start;
                char var_name[256];
                strncpy(var_name, var_start, var_len);
                var_name[var_len] = '\0';

                if (strcmp(var_name, "PREFIX") == 0) {
                    strcpy(out, "/usr");
                    out += 3;
                } else if (strcmp(var_name, "ETC_DIR") == 0) {
                    strcpy(out, g_config.etc_dir);
                    out += strlen(g_config.etc_dir);
                } else if (strcmp(var_name, "LIB_DIR") == 0) {
                    strcpy(out, g_config.lib_dir);
                    out += strlen(g_config.lib_dir);
                } else if (strcmp(var_name, "EXE_DIR") == 0) {
                    strcpy(out, g_config.exe_dir);
                    out += strlen(g_config.exe_dir);
                } else if (strcmp(var_name, "RUNTIME_DIR") == 0) {
                    strcpy(out, g_config.runtime_dir);
                    out += strlen(g_config.runtime_dir);
                } else {
                    // Unknown variable, copy as-is
                    *out++ = *ptr;
                }

                ptr = var_end + 1;
                continue;
            }
        }

        *out++ = *ptr++;
    }

    *out = '\0';
    strncpy(dest, result, dest_size - 1);
    dest[dest_size - 1] = '\0';
}








// Parse configuration file
int parse_config(const char *custom_config_path) {
    // Initialize runtime paths
    get_exe_path(g_config.exe_path, sizeof(g_config.exe_path));
    get_exe_dir(g_config.exe_dir, sizeof(g_config.exe_dir));

    // Set runtime directory
    if (getenv("LIGHTMAIL_RUNTIME_DIR")) {
        strncpy(g_config.runtime_dir, getenv("LIGHTMAIL_RUNTIME_DIR"), sizeof(g_config.runtime_dir) - 1);
    } else {
        strncpy(g_config.runtime_dir, "/var/lib/lightmail", sizeof(g_config.runtime_dir) - 1);
    }

    // Find config file
    char *config_path = find_config_file(custom_config_path);
    LOGD("Using config file: %s\n", config_path);

    strncpy(g_config.config_path, config_path, sizeof(g_config.config_path) - 1);

    FILE *file = fopen(config_path, "r");
    if (!file) {
        fprintf(stderr, "Warning: Could not open config file: %s\n", config_path);
        return 0;
    }

    // Set defaults
    strcpy(g_config.db_host, "localhost");
    g_config.db_port = 3306;
    strcpy(g_config.db_user, "root");
    strcpy(g_config.db_password, "");
    strcpy(g_config.db_name, "maildb");
    g_config.db_pool_size = 10;

    g_config.imap_port = 143;
    g_config.imaps_port = 993;
    g_config.max_clients = 100;
    g_config.buffer_size = 8192;
    g_config.session_timeout = 1800;
    strcpy(g_config.log_file, "/var/log/lightmail.log");
    g_config.log_level = 2;

    strcpy(g_config.ssl_cert_file, "${RUNTIME_DIR}/certs/cert.pem");
    strcpy(g_config.ssl_key_file, "${RUNTIME_DIR}/certs/key.pem");

    strcpy(g_config.mail_dir, "${RUNTIME_DIR}/mailboxes");
    strcpy(g_config.temp_dir, "/tmp/lightmail");
    strcpy(g_config.lib_dir, "/usr/lib/lightmail");
    strcpy(g_config.etc_dir, "/etc/lightmail");

    char line[512];
    char section[64] = "";

    while (fgets(line, sizeof(line), file)) {
        trim(line);

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') {
            continue;
        }

        // Check for section
        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            strncpy(section, line + 1, strlen(line) - 2);
            section[strlen(line) - 2] = '\0';
            continue;
        }

        // Parse key=value
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (key && value) {
            trim(key);
            trim(value);

            printf("Config: [%s] \"%s\" = \"%s\"\n", section, key, value); // existing debug output

            if (strcmp(section, "Database") == 0) {
                if (strcmp(key, "host") == 0)
                    strcpy(g_config.db_host, value);
                else if (strcmp(key, "port") == 0)
                    g_config.db_port = atoi(value);
                else if (strcmp(key, "user") == 0)
                    strcpy(g_config.db_user, value);
                else if (strcmp(key, "password") == 0)
                    strcpy(g_config.db_password, value);
                else if (strcmp(key, "database") == 0)
                    strcpy(g_config.db_name, value);
                else if (strcmp(key, "pool_size") == 0)
                    g_config.db_pool_size = atoi(value);
            } else if (strcmp(section, "Server") == 0) {
                if (strcmp(key, "imap_port") == 0)
                    g_config.imap_port = atoi(value);
                else if (strcmp(key, "imaps_port") == 0)
                    g_config.imaps_port = atoi(value);
                else if (strcmp(key, "max_clients") == 0)
                    g_config.max_clients = atoi(value);
                else if (strcmp(key, "buffer_size") == 0)
                    g_config.buffer_size = atoi(value);
                else if (strcmp(key, "session_timeout") == 0)
                    g_config.session_timeout = atoi(value);
                else if (strcmp(key, "log_file") == 0)
                    strcpy(g_config.log_file, value);
                else if (strcmp(key, "log_level") == 0)
                    g_config.log_level = atoi(value);
            } else if (strcmp(section, "SSL") == 0) {
                if (strcmp(key, "cert_file") == 0)
                    strcpy(g_config.ssl_cert_file, value);
                else if (strcmp(key, "key_file") == 0)
                    strcpy(g_config.ssl_key_file, value);
            } else if (strcmp(section, "Paths") == 0) {
                if (strcmp(key, "mail_dir") == 0)
                    strcpy(g_config.mail_dir, value);
                else if (strcmp(key, "temp_dir") == 0)
                    strcpy(g_config.temp_dir, value);
                else if (strcmp(key, "lib_dir") == 0)
                    strcpy(g_config.lib_dir, value);
                else if (strcmp(key, "etc_dir") == 0)
                    strcpy(g_config.etc_dir, value);
            }
        }
    }

    fclose(file);

    // Expand path variables
    char expanded[PATH_MAX];

    expand_path(expanded, sizeof(expanded), g_config.ssl_cert_file);
    strcpy(g_config.ssl_cert_file, expanded);

    expand_path(expanded, sizeof(expanded), g_config.ssl_key_file);
    strcpy(g_config.ssl_key_file, expanded);

    expand_path(expanded, sizeof(expanded), g_config.mail_dir);
    strcpy(g_config.mail_dir, expanded);

    expand_path(expanded, sizeof(expanded), g_config.log_file);
    strcpy(g_config.log_file, expanded);

    // Ensure directories exist
    mkdir(g_config.mail_dir, 0755);
    mkdir(dirname(g_config.ssl_cert_file), 0755);
    mkdir(dirname(g_config.ssl_key_file), 0755);

    return 1;
}

// Get configuration values
const char *get_config_path() { return g_config.config_path; }
const char *get_exe_path_str() { return g_config.exe_path; }
const char *get_exe_dir_str() { return g_config.exe_dir; }
const char *get_runtime_dir() { return g_config.runtime_dir; }

const char *get_db_host() { return g_config.db_host; }
int get_db_port() { return g_config.db_port; }
const char *get_db_user() { return g_config.db_user; }
const char *get_db_password() { return g_config.db_password; }
const char *get_db_name() { return g_config.db_name; }
int get_db_pool_size() { return g_config.db_pool_size; }

int get_imap_port() { return g_config.imap_port; }
int get_imaps_port() { return g_config.imaps_port; }
int get_max_clients() { return g_config.max_clients; }
int get_buffer_size() { return g_config.buffer_size; }
int get_session_timeout() { return g_config.session_timeout; }
const char *get_log_file() { return g_config.log_file; }
int get_log_level() { return g_config.log_level; }

const char *get_ssl_cert_file() { return g_config.ssl_cert_file; }
const char *get_ssl_key_file() { return g_config.ssl_key_file; }

const char *get_mail_dir() { return g_config.mail_dir; }
const char *get_temp_dir() { return g_config.temp_dir; }
const char *get_lib_dir() { return g_config.lib_dir; }
const char *get_etc_dir() { return g_config.etc_dir; }

// Print configuration (for debugging)
void print_config() {
    printf("Configuration loaded from: %s\n", g_config.config_path);
    printf("Executable path: %s\n", g_config.exe_path);
    printf("Executable directory: %s\n", g_config.exe_dir);
    printf("Runtime directory: %s\n", g_config.runtime_dir);
    printf("\n");
    printf("Database: %s@%s:%d/%s\n", g_config.db_user, g_config.db_host, g_config.db_port, g_config.db_name);
    printf("Server ports: IMAP=%d, IMAPS=%d\n", g_config.imap_port, g_config.imaps_port);
    printf("Max clients: %d\n", g_config.max_clients);
    printf("Log file: %s (level: %d)\n", g_config.log_file, g_config.log_level);
    printf("SSL cert: %s\n", g_config.ssl_cert_file);
    printf("SSL key: %s\n", g_config.ssl_key_file);
    printf("Mail directory: %s\n", g_config.mail_dir);
}