#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define SALT "IMAP_SERVER_SALT"

typedef struct {
    char username[64];
    char password_hash[65]; // SHA256 hex string (64 chars + null)
} User;

// Simple in-memory user database (for demonstration)
User users[] = {
    {"user", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}, // "password" hashed
    {"test", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}  // "test" hashed
};
int user_count = 2;

// Simple SHA256 hash function (requires OpenSSL)
void hash_password(const char* password, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Update(&sha256, SALT, strlen(SALT));
    SHA256_Final(hash, &sha256);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
    }
    output[64] = '\0';
}

int authenticate_user_hash(const char* username, const char* password) {
    char hash[65];
    hash_password(password, hash);
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password_hash, hash) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// Add a new user (for registration)
int add_user(const char* username, const char* password) {
    // Check if user already exists
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return 0;
        }
    }
    
    // Add new user (in real implementation, save to database)
    // This is simplified for demonstration
    
    return 1;
}