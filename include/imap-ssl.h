#ifndef IMAP_SSL_H
#define IMAP_SSL_H
#include <openssl/ssl.h>
#include <pthread.h>

SSL_CTX *init_ssl(void);
void *ssl_server_thread(void *arg);
#endif // IMAP_SSL_H