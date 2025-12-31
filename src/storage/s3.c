#include "s3.h"
#include "conf.h"
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static S3Client s3;

void s3_config_callback(const char *section, const char *key, const char *value, void *ctx) {
    S3Client *s3 = (S3Client *)ctx;
    if (strcmp(key, "endpoint") == 0) {
        s3->endpoint = strdup(value);
    } else if (strcmp(key, "region") == 0) {
        s3->region = strdup(value);
    } else if (strcmp(key, "access_key") == 0) {
        s3->access_key = strdup(value);
    } else if (strcmp(key, "secret_key") == 0) {
        s3->secret_key = strdup(value);
    } else if (strcmp(key, "bucket") == 0) {
        s3->bucket = strdup(value);
    } else if (strcmp(key, "use_ssl") == 0) {
        s3->use_ssl = (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0);
    }
}

int s3_init() {
    get_config_section("s3", s3_config_callback, &s3);

    printf("S3 Config:\n");
    printf(" Endpoint: %s\n", s3.endpoint);
    printf(" Region: %s\n", s3.region);
    printf(" Access Key: %s\n", s3.access_key);
    printf(" Bucket: %s\n", s3.bucket);
    printf(" Use SSL: %s\n", s3.use_ssl ? "true" : "false");
    curl_global_init(CURL_GLOBAL_ALL);
    return EXIT_SUCCESS;
}

// Generate AWS signature v4
char *generate_aws_signature_v4(const char *method, const char *canonical_uri, const char *query_string, const char *headers, const char *payload_hash, const char *date, const char *region, const char *service) {
    // Implementation of AWS Signature Version 4
    // This is a simplified version - in production, use AWS SDK
    char canonical_request[4096];
    char string_to_sign[4096];

    // Create canonical request
    snprintf(canonical_request, sizeof(canonical_request), "%s\n%s\n%s\n%s\n\n%s\n%s", method, canonical_uri, query_string, headers, "", payload_hash);

    // Create string to sign
    snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s", date, date, region, service, sha256_hash(canonical_request));

    // Calculate signature (simplified)
    return calculate_signature(string_to_sign, date, region, service);
}

// Upload to S3
char *s3_upload_message(int account_id, int mailbox_id, int message_uid, const char *data, size_t size, const char *content_type) {

    // Generate S3 key
    char *s3_key = s3_generate_key(account_id, mailbox_id, message_uid);

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(s3_key);
        return NULL;
    }

    char url[1024];
    snprintf(url, sizeof(url), "%s/%s/%s", s3.endpoint, s3.bucket, s3_key);

    struct curl_slist *headers = NULL;

    // Generate AWS signature
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    char date[64];
    strftime(date, sizeof(date), "%Y%m%dT%H%M%SZ", tm);

    char signature[512];
    // Generate signature header

    headers = curl_slist_append(headers, "x-amz-content-sha256: UNSIGNED-PAYLOAD");
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READDATA, fmemopen((void *)data, size, "rb"));
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(s3_key);
        return NULL;
    }

    return s3_key;
}

/* Upload message from a FILE* (streaming) to avoid keeping full message in memory */
char *s3_upload_message_file(int account_id, int mailbox_id, int message_uid, FILE *file, size_t size, const char *content_type) {

    char *s3_key = s3_generate_key(account_id, mailbox_id, message_uid);

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(s3_key);
        return NULL;
    }

    char url[1024];
    snprintf(url, sizeof(url), "%s/%s/%s", s3.endpoint, s3.bucket, s3_key);

    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "x-amz-content-sha256: UNSIGNED-PAYLOAD");
    {
        char ct_header[128];
        snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type ? content_type : "application/octet-stream");
        headers = curl_slist_append(headers, ct_header);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READDATA, file);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(s3_key);
        return NULL;
    }

    return s3_key;
}

/* Download S3 object into a temporary file and return FILE* (caller must fclose). Returns NULL on failure. */
FILE *s3_download_message_file(const char *s3_key, size_t *size) {
    if (!s3_key)
        return NULL;

    char url[1024];
    snprintf(url, sizeof(url), "%s/%s/%s", s3.endpoint, s3.bucket, s3_key);

    FILE *tmp = tmpfile();
    if (!tmp)
        return NULL;

    CURL *curl = curl_easy_init();
    if (!curl) {
        fclose(tmp);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, tmp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        fclose(tmp);
        return NULL;
    }

    double downloaded = 0.0;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &downloaded);
    if (size)
        *size = (size_t)downloaded;

    curl_easy_cleanup(curl);

    rewind(tmp);
    return tmp;
}

char *s3_download_message(const char *s3_key, size_t *size) {
}

bool s3_delete_message(const char *s3_key) {
}

// Generate S3 key
char *s3_generate_key(int account_id, int mailbox_id, int message_uid) {
    char *key = malloc(256);
    snprintf(key, 256, "accounts/%d/mailboxes/%d/messages/%d.eml", account_id, mailbox_id, message_uid);
    return key;
}

char *sha256_hash(const char *input) {
    static char outputBuffer[65];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(outputBuffer + (i * 2), 3, "%02x", hash[i]);
    }
    outputBuffer[64] = '\0';
    return outputBuffer;
}

void hmac_sha256(const void *key, int key_len, const char *data, unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, key_len, (unsigned char *)data, strlen(data), out, &len);
}

char *calculate_signature(const char *to_sign, const char *date, const char *region, const char *service) {
    unsigned char kDate[32], kRegion[32], kService[32], kSigning[32], kFinal[32];

    // 1. Initial key = "AWS4" + Secret Key
    char secret_key_prefixed[256];
    snprintf(secret_key_prefixed, sizeof(secret_key_prefixed), "AWS4%s", s3.secret_key);

    // 2. Derive keys step-by-step
    hmac_sha256(secret_key_prefixed, strlen(secret_key_prefixed), date, kDate);
    hmac_sha256(kDate, 32, region, kRegion);
    hmac_sha256(kRegion, 32, service, kService);
    hmac_sha256(kService, 32, "aws4_request", kSigning);

    // 3. Final signature of the "String to Sign"
    hmac_sha256(kSigning, 32, to_sign, kFinal);

    // 4. Hex encode the final result
    char *signature_hex = malloc(65);
    for (int i = 0; i < 32; i++) {
        snprintf(signature_hex + (i * 2), 3, "%02x", kFinal[i]);
    }
    signature_hex[64] = '\0';

    return signature_hex;
}

// Initialize S3 client
// bool s3_init(const char *endpoint, const char *region, const char *access_key, const char *secret_key, bool use_ssl) {
//     s3.endpoint = strdup(endpoint);
//     s3.region = strdup(region);
//     s3.access_key = strdup(access_key);
//     s3.secret_key = strdup(secret_key);
//     s3.use_ssl = use_ssl;

//     curl_global_init(CURL_GLOBAL_ALL);
//     return true;
// }

// Cleanup S3
void s3_cleanup(void) {
    free(s3.endpoint);
    free(s3.region);
    free(s3.access_key);
    free(s3.secret_key);
    curl_global_cleanup();
}