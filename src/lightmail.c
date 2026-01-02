#include "lightmail.h"
#include "db.h"
#include "imap.h"
#include "lmtp.h"
#include "lmtp_queue.h"
#include "lock.h"
#include "log.h"
#include "metrics.h"
#include "parser.h"
#include "pop3.h"
// #include "shutdown.h"
#include <dlfcn.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Command line options structure
typedef struct {
    char config_file[256];
    int reload;
    int help;
    int version;
    int stop;
} CommandOptions;

void args_callback(const char *k, const char *v, void *ctx) {

    CommandOptions *s = (CommandOptions *)ctx;
    if (!k || strlen(k) < 2) {
        return;
    }

    while (k[0] == '-')
        k++;
    if (strlen(k) == 0)
        return;

    if (strlen(k) == 1) {
        switch (*k) {
        case 'c':
            if (v) { // Always check if v is NULL (user forgot the filename)
                strncpy(s->config_file, v, sizeof(s->config_file) - 1);
                s->config_file[sizeof(s->config_file) - 1] = '\0';
            } else {
                fprintf(stderr, "Error: Option -c requires a configuration file path.\n");
            }
            break;
        case 'h':
            s->help = 1;
            break;
        case 'V':
            s->version = 1;
            break;
        default:
            printf("Unknown option: %s\n", k);
            break;
        }
    }
    if (strcmp(k, "stop") == 0) {
        s->stop = 1;
        return;
    }
    if (strcmp(k, "reload") == 0) {
        s->reload = 1;
        return;
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

/* startup_notify_fd is used by child to notify parent of success/failure during startup */
static int startup_notify_fd = -1;

int main(int argc, char *argv[]) {

    CommandOptions opts = {0};
    parse_command_line(argc, argv, args_callback, &opts);

    if (opts.stop) {
        printf("Stopping LightMail IMAP Server v1.0\n");
        stop_services();
        return EXIT_SUCCESS;
    }

    if (opts.help) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (opts.version) {
        print_version();
        return EXIT_SUCCESS;
    }

    printf("LightMail Server v1.0\n");
    const char *config_path = "/etc/lightmail/lightmail.conf";
    if (opts.config_file[0] != '\0') {
        config_path = opts.config_file;
    }

    if (init_config(config_path) == EXIT_FAILURE) {
        printf("Failed to load configuration: %s\n", config_path);
        fprintf(stderr, "Failed to load configuration: %s\n", config_path);
        LOGE("Failed to load configuration");
        return EXIT_FAILURE;
    }

    /* Initialize logging using configured path if provided so the daemon writes to file by default */
    const char *lpath = get_config_value("logging", "path");
    if (lpath) {
        if (log_init(lpath, LOG_OUTPUT_FILE) != 0) {
            log_init(NULL, LOG_OUTPUT_STDOUT);
        }
    } else {
        log_init(NULL, LOG_OUTPUT_STDOUT);
    }

    /* Initialize database connections */
    if (db_init() == EXIT_FAILURE) {
        LOGE("Database initialization failed, aborting startup");
        exit(1);
    }

    /* Initialize IMAP server */
    if (imap_init() == EXIT_FAILURE) {
        LOGE("IMAP server failed to start, aborting startup");
        exit(1);
    }


    /* Change to root directory to avoid locking current directory */
    if (chdir("/") != 0) {
        /* If can't change to root, try /tmp */
        chdir("/tmp");
    }
    int devnull = open("/dev/null", O_RDWR);
    if (devnull != -1) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2)
            close(devnull);
    }

    run_in_background(imap_start, lpath);
    run_in_background(lmtp_start, lpath);
    run_in_background(pop3_start, lpath);

    /* Start metrics server if configured */
    int metrics_port = get_config_int("service", "metrics_port", 0);
    if (metrics_port > 0) {
        metrics_init(metrics_port);
    }

    /* Start memory sampler if configured */
    int mem_interval = get_config_int("service", "memory_sampler_interval", 0);
    if (mem_interval > 0) {
        memory_sampler_init(mem_interval);
    }

    lmtp_queue_init(get_config_int("service", "lmtp_queue_capacity", 256));
}
