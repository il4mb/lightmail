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
    src/imap/imap.c \
    src/imap/imap-client.c \
    src/imap/imap-send.c \
    src/imap/imap-ssl.c 

lightmail_LDADD = -lmysqlclient -lcurl -lssl -lcrypto -lpthread -lcrypt 

run: lightmail
	./lightmail -c ../config/lightmail.conf
