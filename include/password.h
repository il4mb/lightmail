#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdbool.h>

// Hash password using bcrypt
char* create_password(const char *password);

// Verify password against bcrypt hash
bool verify_password(const char *password, const char *hash);
#endif