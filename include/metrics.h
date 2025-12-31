#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize metrics subsystem and start HTTP server on the given port (0 = disabled) */
int metrics_init(int port);
int metrics_get_listen_port(void);
void metrics_shutdown(void);

/* Memory sampler */
int memory_sampler_init(int interval_seconds);
void memory_sampler_shutdown(void);

/* Counters and gauges (thread-safe) */
void metrics_inc_imap_sessions(void);
void metrics_dec_imap_sessions(void);
void metrics_inc_auth_failures(void);
void metrics_inc_spam_rejections(void);
void metrics_set_lmtp_queue_depth(uint64_t v);
void metrics_inc_lmtp_queue_depth(void);
void metrics_dec_lmtp_queue_depth(void);
void metrics_record_s3_upload_ms(uint64_t ms);
void metrics_record_mysql_query_ms(uint64_t ms);
void metrics_record_memory_pressure_bytes(uint64_t bytes);

#ifdef __cplusplus
}
#endif

#endif
