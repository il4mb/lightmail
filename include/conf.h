#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#define PATH_MAX 4096


// Configuration structure
typedef struct {
    char db_host[256];
    int db_port;
    char db_user[256];
    char db_password[256];
    char db_name[256];
    int db_pool_size;
    
    int imap_port;
    int imaps_port;
    int max_clients;
    int buffer_size;
    int session_timeout;
    char log_file[PATH_MAX];
    int log_level;
    
    char ssl_cert_file[PATH_MAX];
    char ssl_key_file[PATH_MAX];
    
    char mail_dir[PATH_MAX];
    char temp_dir[PATH_MAX];
    char lib_dir[PATH_MAX];
    char etc_dir[PATH_MAX];
    
    // Runtime detected paths
    char config_path[PATH_MAX];
    char exe_path[PATH_MAX];
    char exe_dir[PATH_MAX];
    char runtime_dir[PATH_MAX];
} ServerConfig;

const ServerConfig *get_config(void);

// Configuration parsing
int parse_config(const char *custom_config_path);

// Path information
const char* get_config_path(void);
const char* get_exe_path_str(void);
const char* get_exe_dir_str(void);
const char* get_runtime_dir(void);

// Database configuration
const char* get_db_host(void);
int get_db_port(void);
const char* get_db_user(void);
const char* get_db_password(void);
const char* get_db_name(void);
int get_db_pool_size(void);

// Server configuration
int get_imap_port(void);
int get_imaps_port(void);
int get_max_clients(void);
int get_buffer_size(void);
int get_session_timeout(void);
const char* get_log_file(void);
int get_log_level(void);

// SSL configuration
const char* get_ssl_cert_file(void);
const char* get_ssl_key_file(void);

// Paths configuration
const char* get_mail_dir(void);
const char* get_temp_dir(void);
const char* get_lib_dir(void);
const char* get_etc_dir(void);

// Debug
void print_config(void);

#endif