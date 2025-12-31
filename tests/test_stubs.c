#include "conf.h"

/* Minimal stub for get_config_section used by s3.c in tests */
void get_config_section(const char *section, config_section_callback_t callback, void *ctx) {
    (void)section;
    (void)callback;
    (void)ctx;
}
