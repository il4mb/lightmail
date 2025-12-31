#include "parser.h"
#include "conf.h"
#include "log.h"
#include "shutdown.h"
#include <dlfcn.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Command line options structure
typedef struct {
    char config_file[256];
    int daemon_mode;
    int verbose;
    int help;
    int version;
    int test_config;
} CommandOptions;

void args_callback(const char *k, const char *v, void *ctx) {
    CommandOptions *s = (CommandOptions *)ctx;
    // Safety check: k should always exist, but let's be sure
    if (!k || strlen(k) < 2)
        return;

    switch (k[1]) {
        case 'c':
            if (v) { // Always check if v is NULL (user forgot the filename)
                strncpy(s->config_file, v, sizeof(s->config_file) - 1);
                s->config_file[sizeof(s->config_file) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: Option -c requires a configuration file path.\n");
            }
            break;
        case 'd':
            s->daemon_mode = 1;
            break;
        case 'h':
            s->help = 1;
            break;
        case 'V':
            s->version = 1;
            break;
        case 't':
            s->test_config = 1;
            break;
        default:
            printf("Unknown option: %s\n", k);
            break;
    }
}

// Print usage information
void print_usage(const char *progname) {
    printf("LightMail IMAP Server v1.0\n");
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  -c FILE    Use specified configuration file\n");
    printf("  -d         Run as daemon (background process)\n");
    printf("  -v         Verbose output\n");
    printf("  -t         Test configuration and exit\n");
    printf("  -h         Show this help message\n");
    printf("  -V         Show version information\n");
    printf("\n");
    printf("Configuration search order:\n");
    printf("  1. -c option specified file\n");
    printf("  2. ./lightmail.conf\n");
    printf("  3. $EXE_DIR/lightmail.conf\n");
    printf("  4. $EXE_DIR/../config/lightmail.conf\n");
    printf("  5. /etc/lightmail/lightmail.conf\n");
    printf("  6. /usr/local/etc/lightmail/lightmail.conf\n");
    printf("  7. /opt/lightmail/etc/lightmail.conf\n");
    printf("\n");
    printf("Environment variables:\n");
    printf("  LIGHTMAIL_RUNTIME_DIR  Runtime data directory (default: /var/lib/lightmail)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c ./myconfig.conf    # Use custom config\n", progname);
    printf("  %s -d                    # Run as daemon\n", progname);
    printf("  %s -t                    # Test configuration\n", progname);
}

// Print version information
void print_version() {
    printf("LightMail IMAP Server v1.0\n");
    printf("Built on %s %s\n", __DATE__, __TIME__);
    printf("Copyright (c) 2024 LightMail Project\n");
    printf("License: MIT\n");
}

// Daemonize process
void daemonize() {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        // Parent process exits
        exit(EXIT_SUCCESS);
    }

    // Child process continues
    umask(0);

    // Create new session
    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    // Change working directory
    if (chdir("/") < 0) {
        perror("chdir failed");
        exit(EXIT_FAILURE);
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Reopen to /dev/null
    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
}

int main(int argc, char *argv[]) {

    setup_signal_handlers();
    LOG_INIT();

    CommandOptions opts = {0};
    parse_command_line(argc, argv, args_callback, &opts);

    // Handle special options
    if (opts.help) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (opts.version) {
        print_version();
        return EXIT_SUCCESS;
    }

    if (init_config(opts.config_file) == EXIT_FAILURE) {
        fprintf(stderr, "Failed to initialize configuration\n");
        return EXIT_FAILURE;
    }

    // Daemonize if requested
    if (opts.daemon_mode) {
        daemonize();
    }

    pid_t pid = fork();

    if (pid < 0) {
        LOGE("Fork failed for IMAP server");
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // CHILD PROCESS → IMAP
        // start_imap();
        _exit(0);
    }


    free_config();
    LOG_CLOSE();
    return EXIT_SUCCESS;
}
