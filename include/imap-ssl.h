#ifndef IMAP_SSL_H
#define IMAP_SSL_H
#include <openssl/ssl.h>
#include <pthread.h>
void *ssl_server_thread(void *arg);
#endif // IMAP_SSL_H