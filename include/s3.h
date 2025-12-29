#ifndef S3_H
#define S3_H

#include <stddef.h>
#include <stdbool.h>

// S3 configuration
typedef struct
{
    char *endpoint;
    char *region;
    char *bucket;
    char *access_key;
    char *secret_key;
    bool use_ssl;
} S3Config;

char *sha256_hash(const char *input);
char *calculate_signature(const char *to_sign, const char *date, const char *region, const char *service);

// Initialize S3 client
bool s3_init(const char *endpoint, const char *region,
             const char *access_key, const char *secret_key,
             bool use_ssl);

// Upload message body to S3
char *s3_upload_message(int account_id, int mailbox_id, int message_uid,
                        const char *data, size_t size,
                        const char *content_type);

// Download message body from S3
char *s3_download_message(const char *s3_key, size_t *size);

// Delete message from S3
bool s3_delete_message(const char *s3_key);

// Generate S3 key for message
char *s3_generate_key(int account_id, int mailbox_id, int message_uid);

// Cleanup S3 client
void s3_cleanup(void);

#endif