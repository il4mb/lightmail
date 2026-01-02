#include <lightmail.h>
#include "../include/metrics.h"
#include <stdint.h>

/* Minimal stub for get_config_section used by s3.c in tests */
void get_config_section(const char *section, config_section_callback_t callback, void *ctx) {
    (void)section;
    (void)callback;
    (void)ctx;
}

/* Provide a no-op metrics shim for tests that don't link metrics.c */
void metrics_record_s3_upload_ms(uint64_t ms) {
    (void)ms;
}
