#include "lightmail.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "shutdown.h"
#include "pop3.h"
#include "lmtp.h"
#include "lmtp_queue.h"
#include "metrics.h"
#include "imap.h"
#include "db.h"
#include "lock.h"
#include <dlfcn.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <poll.h>

// Thread wrappers to use with pthread_create
static void *start_pop3_thread(void *arg) { (void)arg; start_pop3(); return NULL; }
static void *start_lmtp_thread(void *arg) { (void)arg; start_lmtp(); return NULL; }

// Command line options structure
typedef struct {
    char config_file[256];
    int reload;
    int help;
    int version;
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
    case 'h':
        s->help = 1;
        break;
    case 'V':
        s->version = 1;
        break;
    case 'r':
        s->reload = 1;
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

/* startup_notify_fd is used by child to notify parent of success/failure during startup */
static int startup_notify_fd = -1;

int main(int argc, char *argv[]) {

    CommandOptions opts = {0};
    parse_command_line(argc, argv, args_callback, &opts);

    if(opts.help) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if(opts.version) {
        print_version();
        return EXIT_SUCCESS;
    }



    if (opts.reload == 0 && is_already_running()) {
        fprintf(stderr, "LightMail is already running\n");
        return EXIT_FAILURE;
    }

    if (init_config(opts.config_file) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }
    LOGI("Using configuration file: %s", opts.config_file);

    /* Create a pipe so child can notify parent of startup success/failure */
    int status_pipe[2];
    if (pipe(status_pipe) == 0) {
        /* status_pipe[0] = read end (parent), status_pipe[1] = write end (child) */
        /* mark fds close-on-exec so they don't leak to child execs */
        /* parent will close write end after fork, child closes read end */
    } else {
        status_pipe[0] = status_pipe[1] = -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid > 0) {
        /* Parent: wait for child to report startup status, with timeout */
        if (status_pipe[0] >= 0) close(status_pipe[1]);
        int rc = 0;
        if (status_pipe[0] >= 0) {
            struct pollfd pfd;
            pfd.fd = status_pipe[0];
            pfd.events = POLLIN;
            int poll_rc = poll(&pfd, 1, 3000); /* 3s timeout */
            if (poll_rc == 1 && (pfd.revents & POLLIN)) {
                int child_status = -1;
                ssize_t r = read(status_pipe[0], &child_status, sizeof(child_status));
                (void)r;
                if (child_status == 0) {
                    printf("LightMail started (PID %d)\n", pid);
                    rc = EXIT_SUCCESS;
                } else {
                    fprintf(stderr, "LightMail failed to start (see logs for details).\n");
                    rc = EXIT_FAILURE;
                }
            } else if (poll_rc == 0) {
                fprintf(stderr, "LightMail startup timed out, child did not report status (see logs for details).\n");
                rc = EXIT_FAILURE;
            } else {
                /* poll error */
                perror("poll error during startup");
                rc = EXIT_FAILURE;
            }
            close(status_pipe[0]);
        } else {
            /* no pipe available, fallback to optimistic start */
            fprintf(stderr, "LightMail started without status pipe (PID %d). Check logs for errors.\n", pid);
            rc = EXIT_SUCCESS;
        }
        return rc;
    }

    // ---- CHILD (DAEMON) ----
    /* Child closes the read end of the pipe and keeps write end to notify parent */
    if (status_pipe[0] >= 0) {
        close(status_pipe[0]);
        startup_notify_fd = status_pipe[1];
    }

    umask(0);

    if (setsid() < 0) {
        if (startup_notify_fd >= 0) {
            int err = 1; (void)write(startup_notify_fd, &err, sizeof(err)); close(startup_notify_fd);
        }
        _exit(1);
    }

    chdir("/");

    int fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2)
        close(fd);

    // Now safe to initialize logging & signals
    setup_signal_handlers();
    /* Initialize logging using configured path if provided so the daemon writes to file by default */
    const char *lpath = get_config_value("logging", "path");
    if (lpath) {
        if (log_init(lpath, LOG_OUTPUT_FILE) != 0) {
            /* fallback to stdout if file init fails */
            log_init(NULL, LOG_OUTPUT_STDOUT);
        }
    } else {
        log_init(NULL, LOG_OUTPUT_STDOUT);
    }

    /* Initialize database connections */
    if (db_init() == EXIT_FAILURE) {
        LOGE("Database initialization failed, aborting startup");
        /* Notify parent of failure if pipe available */
        if (startup_notify_fd >= 0) {
            int err = 1;
            (void)write(startup_notify_fd, &err, sizeof(err));
            close(startup_notify_fd);
        }
        _exit(1);
    }

    /* Start POP3 service */
    pthread_t pop3_thread;
    if (pthread_create(&pop3_thread, NULL, start_pop3_thread, NULL) == 0) {
        pthread_detach(pop3_thread);
    }

    /* Start LMTP service */
    pthread_t lmtp_thread;
    if (pthread_create(&lmtp_thread, NULL, start_lmtp_thread, NULL) == 0) {
        pthread_detach(lmtp_thread);
    }

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

    /* Start LMTP queue manager */
    lmtp_queue_init(get_config_int("service", "lmtp_queue_capacity", 256));

    /* Start IMAP server (runs in its own thread now) */
    if (start_imap() != 0) {
        LOGE("IMAP server failed to start, aborting startup");
        if (startup_notify_fd >= 0) {
            int err = 1;
            (void)write(startup_notify_fd, &err, sizeof(err));
            close(startup_notify_fd);
        }
        _exit(1);
    }

    /* Notify parent we're up */
    if (startup_notify_fd >= 0) {
        int ok = 0;
        (void)write(startup_notify_fd, &ok, sizeof(ok));
        close(startup_notify_fd);
    }

    /* Child continues running the services (IMAP runs in its own thread) */

    // Graceful shutdown
    free_config();
    LOG_CLOSE();
    _exit(0);
}
