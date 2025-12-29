#include "s3.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static S3Config s3_config;

// Generate AWS signature v4
char* generate_aws_signature_v4(const char *method, const char *canonical_uri,
                               const char *query_string, const char *headers,
                               const char *payload_hash, const char *date,
                               const char *region, const char *service) {
    // Implementation of AWS Signature Version 4
    // This is a simplified version - in production, use AWS SDK
    char canonical_request[4096];
    char string_to_sign[4096];
    
    // Create canonical request
    snprintf(canonical_request, sizeof(canonical_request),
        "%s\n%s\n%s\n%s\n\n%s\n%s",
        method, canonical_uri, query_string, headers,
        "", payload_hash);
    
    // Create string to sign
    snprintf(string_to_sign, sizeof(string_to_sign),
        "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
        date, date, region, service,
        sha256_hash(canonical_request));
    
    // Calculate signature (simplified)
    return calculate_signature(string_to_sign, date, region, service);
}

// Upload to S3
char* s3_upload_message(int account_id, int mailbox_id, int message_uid,
                       const char *data, size_t size, 
                       const char *content_type) {
    
    // Generate S3 key
    char *s3_key = s3_generate_key(account_id, mailbox_id, message_uid);
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(s3_key);
        return NULL;
    }
    
    char url[1024];
    snprintf(url, sizeof(url), "%s/%s/%s",
             s3_config.endpoint, s3_config.bucket, s3_key);
    
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
    curl_easy_setopt(curl, CURLOPT_READDATA, fmemopen((void*)data, size, "rb"));
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

// Generate S3 key
char* s3_generate_key(int account_id, int mailbox_id, int message_uid) {
    char *key = malloc(256);
    snprintf(key, 256, "accounts/%d/mailboxes/%d/messages/%d.eml",
             account_id, mailbox_id, message_uid);
    return key;
}

char *sha256_hash(const char *input){
    static char outputBuffer[65];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
    return outputBuffer;
}

void hmac_sha256(const void *key, int key_len, const char *data, unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, key_len, (unsigned char*)data, strlen(data), out, &len);
}

char* calculate_signature(const char *to_sign, const char *date, 
                          const char *region, const char *service) {
    unsigned char kDate[32], kRegion[32], kService[32], kSigning[32], kFinal[32];
    
    // 1. Initial key = "AWS4" + Secret Key
    char secret_key_prefixed[256];
    snprintf(secret_key_prefixed, sizeof(secret_key_prefixed), "AWS4%s", s3_config.secret_key);

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
        sprintf(signature_hex + (i * 2), "%02x", kFinal[i]);
    }
    signature_hex[64] = '\0';
    
    return signature_hex;
}

// Initialize S3 client
bool s3_init(const char *endpoint, const char *region, 
             const char *access_key, const char *secret_key,
             bool use_ssl) {
    s3_config.endpoint = strdup(endpoint);
    s3_config.region = strdup(region);
    s3_config.access_key = strdup(access_key);
    s3_config.secret_key = strdup(secret_key);
    s3_config.use_ssl = use_ssl;
    
    curl_global_init(CURL_GLOBAL_ALL);
    return true;
}

// Cleanup S3
void s3_cleanup(void) {
    free(s3_config.endpoint);
    free(s3_config.region);
    free(s3_config.access_key);
    free(s3_config.secret_key);
    curl_global_cleanup();
}