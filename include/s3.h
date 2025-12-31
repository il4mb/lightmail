#ifndef S3_H
#define S3_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char *endpoint;
    char *region;
    char *access_key;
    char *secret_key;
    char *bucket;
    bool use_ssl;
} S3Client;

typedef struct {
    char *data;
    size_t size;
} S3Response;

static S3Client *s3_client_new(const char *endpoint, const char *region, const char *bucket, const char *access_key, const char *secret_key) {

    S3Client *client = calloc(1, sizeof(S3Client));
    if (!client)
        return NULL;

    client->endpoint = strdup(endpoint);
    client->region = strdup(region);
    client->bucket = strdup(bucket);
    client->access_key = strdup(access_key);
    client->secret_key = strdup(secret_key);

    return client;
}

char *sha256_hash(const char *input);
char *calculate_signature(const char *to_sign, const char *date, const char *region, const char *service);
int s3_init();
char *s3_upload_message(int account_id, int mailbox_id, int message_uid, const char *data, size_t size, const char *content_type);
char *s3_download_message(const char *s3_key, size_t *size);
bool s3_delete_message(const char *s3_key);
char *s3_generate_key(int account_id, int mailbox_id, int message_uid);
void s3_cleanup(void);

#endif