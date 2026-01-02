#ifndef LIGHTMAIL_H
#define LIGHTMAIL_H

#include <log.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_SECTIONS 100
#define MAX_CONF_MAP_ENTRIES 500
#define PID_FILE "/etc/lightmail/pids"
#define FALLBACK_PID_FILE "/tmp/lightmail.pids"
#define CONFIG_DIR "/etc/lightmail"

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

/* Config API */
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

/* Global variable to track which PID file is being used */
static __attribute__((unused)) const char *current_pid_file = PID_FILE;

/* Directory utilities */
static __attribute__((unused)) int ensure_dir_exists(const char *path) {
    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // Directory already exists
        } else {
            errno = ENOTDIR;
            return -1; // Path exists but is not a directory
        }
    }

    // Create directory with 0755 permissions
    if (mkdir(path, 0755) == 0) {
        return 0; // Directory created successfully
    }

    // If parent directories don't exist, try to create them
    if (errno == ENOENT) {
        // Create parent directories
        char *path_copy = strdup(path);
        if (!path_copy) {
            errno = ENOMEM;
            return -1;
        }

        char *p = path_copy;
        while (*p == '/')
            p++; // Skip leading slashes

        while ((p = strchr(p, '/')) != NULL) {
            *p = '\0';
            mkdir(path_copy, 0755);
            *p = '/';
            p++;
        }

        free(path_copy);

        // Try creating the final directory again
        if (mkdir(path, 0755) == 0) {
            return 0;
        }
    }

    return -1; // Failed to create directory
}

/* Other API */
__attribute__((unused)) char *normalize_path(const char *path);

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

static __attribute__((unused)) int save_pid(pid_t pid) {
    const char *pid_file_to_use = PID_FILE;
    int use_fallback = 0;

    // Try to create config directory and save to primary location first
    if (ensure_dir_exists(CONFIG_DIR) < 0) {
        if (errno == EACCES) {
            // Permission denied, fallback to /tmp
            use_fallback = 1;
            pid_file_to_use = FALLBACK_PID_FILE;
            printf("Permission denied for %s, falling back to %s\n",
                   CONFIG_DIR, FALLBACK_PID_FILE);
        } else {
            perror("Failed to create config directory");
            return EXIT_FAILURE;
        }
    }

    int fd = open(pid_file_to_use, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        if (errno == EACCES && !use_fallback) {
            // Permission denied for primary file, try fallback
            pid_file_to_use = FALLBACK_PID_FILE;
            fd = open(pid_file_to_use, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("Failed to open PID file (both primary and fallback)");
                return EXIT_FAILURE;
            }
            printf("Permission denied for %s, falling back to %s\n",
                   PID_FILE, FALLBACK_PID_FILE);
        } else if (fd < 0) {
            perror("Failed to open PID file");
            return EXIT_FAILURE;
        }
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        perror("Failed to acquire lock on PID file");
        close(fd);
        return EXIT_FAILURE;
    }

    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d\n", (int)pid);
    write(fd, pid_str, strlen(pid_str));
    close(fd);

    // Update global variable
    current_pid_file = pid_file_to_use;

    return EXIT_SUCCESS;
}

static __attribute__((unused)) void run_in_background(int *(service_func)(void), char *lpath) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        umask(0);

        service_func();
        _exit(0);
    } else if (pid > 0) {
        if (save_pid(pid) == EXIT_FAILURE) {
            printf("Failed to save PID\n");
        }
    }
}

static __attribute__((unused)) int check_process_alive(pid_t pid) {
    // Check if process exists by sending signal 0
    if (kill(pid, 0) == 0) {
        return 1; // Process is alive
    } else if (errno == ESRCH) {
        return 0; // Process does not exist
    } else if (errno == EPERM) {
        return 1; // Process exists but we don't have permission to signal it
    }
    return 0; // Other error, assume process is dead
}

static __attribute__((unused)) void stop_services() {
    FILE *f = NULL;
    const char *pid_file_used = NULL;

    // Try primary PID file first
    f = fopen(PID_FILE, "r");
    if (f) {
        pid_file_used = PID_FILE;
    } else {
        // Try fallback PID file
        f = fopen(FALLBACK_PID_FILE, "r");
        if (f) {
            pid_file_used = FALLBACK_PID_FILE;
            printf("Using fallback PID file: %s\n", FALLBACK_PID_FILE);
        } else {
            printf("No services appear to be running.\n");
            return;
        }
    }

    int pid;
    int pids_found = 0;
    int pids_stopped = 0;

    // First pass: send SIGTERM to all processes
    while (fscanf(f, "%d", &pid) != EOF) {
        pids_found++;
        printf("Stopping process %d...\n", pid);

        if (kill(pid, SIGTERM) < 0) {
            if (errno == ESRCH) {
                printf("  Process %d does not exist\n", pid);
            } else if (errno == EPERM) {
                printf("  No permission to stop process %d\n", pid);
            } else {
                perror("  Failed to send SIGTERM");
            }
        } else {
            pids_stopped++;
        }
    }

    fclose(f);

    if (pids_found == 0) {
        printf("No PIDs found in PID file.\n");
        unlink(pid_file_used);
        return;
    }

    // Wait for processes to terminate gracefully
    printf("Waiting for processes to terminate gracefully...\n");

    // Re-open file to read PIDs again for checking
    f = fopen(pid_file_used, "r");
    if (!f) {
        printf("Failed to reopen PID file for status check\n");
        unlink(pid_file_used);
        return;
    }

    int max_wait_time = 10; // Maximum 10 seconds
    int wait_time = 0;

    while (wait_time < max_wait_time) {
        int all_dead = 1;

        rewind(f); // Go back to beginning of file
        while (fscanf(f, "%d", &pid) != EOF) {
            if (check_process_alive(pid)) {
                all_dead = 0;
                printf("  Process %d still alive...\n", pid);
            }
        }

        if (all_dead) {
            printf("All processes terminated gracefully.\n");
            break;
        }

        sleep(1);
        wait_time++;
    }

    fclose(f);

    // Second pass: if processes are still alive, send SIGKILL
    if (wait_time >= max_wait_time) {
        printf("Some processes did not terminate gracefully, forcing termination...\n");

        f = fopen(pid_file_used, "r");
        if (f) {
            while (fscanf(f, "%d", &pid) != EOF) {
                if (check_process_alive(pid)) {
                    printf("  Force killing process %d...\n", pid);
                    kill(pid, SIGKILL);
                }
            }
            fclose(f);

            // Give SIGKILL a moment to work
            sleep(2);
        }
    }

    // Remove the PID file
    if (unlink(pid_file_used) == 0) {
        printf("PID file removed: %s\n", pid_file_used);
    } else {
        printf("Failed to remove PID file: %s\n", pid_file_used);
    }

    printf("Stopped %d out of %d processes.\n", pids_stopped, pids_found);
}

#endif