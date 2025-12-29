bin_PROGRAMS = lightmail
AM_CPPFLAGS = -I$(top_srcdir)/include

lightmail_SOURCES = \
    lightmail.c \
    shutdown.c \
    config/config.c \
    lib/db.c \
    lib/s3.c \
    lib/auth.c \
    lib/dirs.c \
    lib/mailbox.c \
    lib/password.c \
    servers/imap.c 

lightmail_LDADD = \
    -lmysqlclient \
    -lcurl \
    -lssl \
    -lcrypto \
    -lpthread \
    -lcrypt

run: lightmail
	@echo "Starting LightMail..."
	@./lightmail -c ./config/lightmail.conf