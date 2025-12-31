#ifndef PARSER_H
#define PARSER_H
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Trim whitespace from string
static inline void trim(void *str) {
    if (!str)
        return;

    bool in_quotes = false;
    char *ptr = str;
    char *comment_pos = NULL;

    // 1. Identify the true comment (only if outside quotes)
    while (*ptr) {
        if (*ptr == '"') {
            in_quotes = !in_quotes; // Toggle state
        } else if (*ptr == '#' && !in_quotes) {
            comment_pos = ptr;
            break; // Found a real comment
        }
        ptr++;
    }

    // Terminate at the comment if found
    if (comment_pos)
        *comment_pos = '\0';

    // 2. Find start (skip leading whitespace)
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    // 3. Find end (skip trailing whitespace)
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';

    // 4. Remove surrounding quotes IF they exist
    if (*start == '"' && *end == '"' && end > start) {
        start++;     // Move past first quote
        *end = '\0'; // Overwrite last quote
    }

    // 5. Shift back to original pointer
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

/**
 * @brief Callback for parsed commands.
 * @param key   The flag name (e.g., "-f" or "--file")
 * @param value The associated value, or NULL if it's a boolean flag.
 * @param ctx   User-provided context (to avoid global variables).
 */
typedef void (*cmd_callback_t)(const char *key, const char *value, void *ctx);

/**
 * @brief Callback for parsed configuration entries.
 * @param section The section name in the config file.
 * @param key     The configuration key.
 * @param value   The configuration value.
 * @param ctx     User-provided context (to avoid global variables).
 */
typedef void (*config_callback_t)(const char *section, const char *key, const char *value, void *ctx);

/**
 * @brief Parses command line arguments.
 * Handles: -f value, --file value, --file=value, and boolean -v flags.
 */
static inline void parse_command_line(int argc, char *argv[], cmd_callback_t callback, void *ctx) {
    if (!callback)
        return;

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        // Only process arguments starting with '-'
        if (arg[0] == '-') {
            char *key = arg;
            char *value = NULL;

            // Handle "--key=value" format
            char *equals_pos = strchr(arg, '=');
            if (equals_pos) {
                *equals_pos = '\0'; // Temporarily split string
                value = equals_pos + 1;
                callback(key, value, ctx);
                *equals_pos = '='; // Restore string
                continue;
            }

            // Check if next arg is a value or another flag
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                value = argv[++i]; // Consume next arg as value
            }

            callback(key, value, ctx);
        }
    }
}

/**
 * @brief Parses a configuration file and invokes a callback for each key-value pair.
 * @param filepath Path to the configuration file.
 * @param callback Function to call for each parsed key-value pair.
 * @param ctx      User-provided context (to avoid global variables).
 */
static inline int parse_config_file(const char *filepath, config_callback_t callback, void *ctx) {
    if (!callback || !filepath)
        return EXIT_FAILURE;

    FILE *file = fopen(filepath, "r");
    if (!file)
        return EXIT_FAILURE;

    char line[512];
    char section[64] = "";

    while (fgets(line, sizeof(line), file)) {
        trim(line);

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') {
            continue;
        }

        // Check for section
        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            strncpy(section, line + 1, strlen(line) - 2);
            section[strlen(line) - 2] = '\0';
            continue;
        }

        // Parse key=value
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (key && value) {
            trim(key);
            trim(value);
            callback(section, key, value, ctx);
        }
    }

    fclose(file);
    return EXIT_SUCCESS;
}

#endif