#ifndef LMTP_QUEUE_H
#define LMTP_QUEUE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int lmtp_queue_init(size_t capacity);
void lmtp_queue_shutdown(void);

/* Set enqueue timeout in milliseconds. 0 = immediate (no wait). */
void lmtp_queue_set_enqueue_timeout_ms(int ms);

/* Enqueue a job. Returns 0 on success, -1 on failure. Ownership of 'path' is copied. */
int lmtp_queue_enqueue(const char *path, int account_id, int mailbox_id, int message_uid, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* LMTP_QUEUE_H */