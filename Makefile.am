bin_PROGRAMS = lightmail
AM_CPPFLAGS = -I$(top_srcdir)/include



lightmail_SOURCES = \
    src/lightmail.c \
    src/core/auth.c \
    src/core/lock.c \
    src/core/password.c \
    src/core/shutdown.c \
    src/core/config.c \
    src/core/dirs.c \
    src/core/mailbox.c \
    src/core/runtime.c \
    src/storage/db.c \
    src/storage/db-account.c \
    src/storage/db-mailbox.c \
    src/storage/db-message.c \
    src/storage/s3.c \
    src/lmtp/lmtp.c \
    src/lmtp/lmtp_session.c \
    src/imap/imap.c \
    src/imap/imap-client.c \
    src/imap/imap-send.c \
    src/imap/imap-ssl.c \
    src/log/log.c \
    src/pop3/pop3.c \
    src/metrics/metrics.c \
    src/metrics/memory_sampler.c \
    src/lmtp/queue.c 

lightmail_LDADD = -lmysqlclient -lcurl -lpthread -lcrypt -lssl -lcrypto 

setcap:
	sudo setcap 'cap_net_bind_service=+ep' lightmail

run: lightmail setcap
	./lightmail -c ../config/lightmail.conf

# Run unit tests
test:
	@./tests/run_tests.sh || (echo "Tests failed"; exit 1)

