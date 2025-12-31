#ifndef POP3_H
#define POP3_H

#ifdef __cplusplus
extern "C" {
#endif

void start_pop3(void);
void pop3_user_login(const char *user);
void pop3_user_login_failed(const char *user);

#ifdef __cplusplus
}
#endif

#endif
