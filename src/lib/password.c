#include "password.h"
#include <stdlib.h>
#include <string.h>
#include <crypt.h>

// Hash password using bcrypt
char *create_password(const char *password) {
    // Generate salt
    char salt[30];
    const char *salt_prefix = "$2y$12$"; // bcrypt with cost factor 12
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    strcpy(salt, salt_prefix);
    for (int i = 0; i < 22; i++)
    {
        salt[7 + i] = charset[rand() % 64];
    }
    salt[29] = '\0';
    // Hash password
    char *hash = crypt(password, salt);
    return strdup(hash);
}
// Verify password against bcrypt hash
bool verify_password(const char *password, const char *hash) {
    char *calculated_hash = crypt(password, hash);
    return (strcmp(calculated_hash, hash) == 0);
}