#include "conf.h"
#include "db.h"
#include "log.h"
#include "s3.h"
#include "shutdown.h"
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
} CommandLineOptions;

// Parse command line arguments
void parse_command_line(int argc, char *argv[], CommandLineOptions *opts) {
    memset(opts, 0, sizeof(CommandLineOptions));

    // Default config file
    strcpy(opts->config_file, "");

    // Parse options
    int opt;
    while ((opt = getopt(argc, argv, "c:dvhtV")) != -1) {
        switch (opt) {
        case 'c': // Config file
            strncpy(opts->config_file, optarg, sizeof(opts->config_file) - 1);
            opts->config_file[sizeof(opts->config_file) - 1] = '\0';
            break;
        case 'd': // Daemon mode
            opts->daemon_mode = 1;
            break;
        case 'v': // Verbose
            opts->verbose = 1;
            break;
        case 't': // Test config
            opts->test_config = 1;
            break;
        case 'h': // Help
            opts->help = 1;
            break;
        case 'V': // Version
            opts->version = 1;
            break;
        case '?':
            fprintf(stderr, "Unknown option: %c\n", optopt);
            exit(EXIT_FAILURE);
        }
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

    CommandLineOptions opts;

    // Parse command line
    parse_command_line(argc, argv, &opts);

    // Handle special options
    if (opts.help) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (opts.version) {
        print_version();
        return EXIT_SUCCESS;
    }

    // Parse configuration
    if (!parse_config(opts.config_file)) {
        fprintf(stderr, "Failed to parse configuration\n");
        return EXIT_FAILURE;
    }

    // Test configuration mode
    if (opts.test_config) {
        printf("Configuration test successful!\n");
        print_config();

        // Test database connection
        printf("\nTesting database connection...\n");
        if (db_init()) {
            printf("Database: OK\n");
            db_cleanup();
        } else {
            printf("Database: FAILED\n");
        }

        return EXIT_SUCCESS;
    }

    // Daemonize if requested
    if (opts.daemon_mode) {
        daemonize();
    }

    // Verbose output
    if (opts.verbose) {
        print_config();
    }

    // Initialize database
    if (!db_init()) {
        fprintf(stderr, "Failed to initialize database\n");
        return EXIT_FAILURE;
    }

    const ServerConfig *cfg = get_config();
    printf("IMAP PORT %d\n", cfg->imap_port);

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // CHILD PROCESS → IMAP
        start_imap();
        _exit(0);
    }

    // PARENT PROCESS continues
    printf("IMAP started in background (pid=%d)\n", pid);

    // Cleanup
    db_cleanup();

    LOG_CLOSE();
    return EXIT_SUCCESS;
}
