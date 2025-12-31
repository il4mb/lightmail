#include "metrics.h"
#include "conf.h"
#include "log.h"
#include <pthread.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

static pthread_t g_mem_thread;
static int g_mem_running = 0;
static int g_interval = 30;

static void *mem_thread_main(void *arg) {
    (void)arg;
    while (g_mem_running) {
        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            uint64_t total = (uint64_t)si.totalram * si.mem_unit;
            uint64_t free = (uint64_t)si.freeram * si.mem_unit;
            uint64_t used = total - free;
            metrics_record_memory_pressure_bytes(used);
        }
        sleep(g_interval);
    }
    return NULL;
}

int memory_sampler_init(int interval_seconds) {
    if (interval_seconds <= 0) return 0;
    g_interval = interval_seconds;
    g_mem_running = 1;
    if (pthread_create(&g_mem_thread, NULL, mem_thread_main, NULL) != 0) {
        g_mem_running = 0;
        return -1;
    }
    LOGI_S("metrics", "Memory sampler started with interval %d s", interval_seconds);
    return 0;
}

void memory_sampler_shutdown(void) {
    if (!g_mem_running) return;
    g_mem_running = 0;
    pthread_join(g_mem_thread, NULL);
}
