AS_IF([test "$PWD" = "$srcdir"], [AC_MSG_ERROR([In-source build is disabled. Use a separate build directory.])])

AC_INIT([lightmail], [0.1], [durianbohong@gmail.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/lightmail.c])


LT_INIT([disable-shared disable-static])
AC_PROG_CC

AC_CHECK_HEADERS([
    mysql/mysql.h
    openssl/evp.h,
    openssl/rand.h,
    syslog.h
    unistd.h
    stdlib.h
    string.h
    systemd/sd-journal.h
    systemd/sd-daemon.h
])

# Check for libsystemd (optional, enables journald support)
PKG_CHECK_MODULES([SYSTEMD], [libsystemd], [HAVE_SYSTEMD=yes], [HAVE_SYSTEMD=no])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "$HAVE_SYSTEMD" = "yes"])
if test "$HAVE_SYSTEMD" = "yes"; then
    AC_DEFINE([HAVE_SYSTEMD], [1], [Define if systemd journal is available])
fi

AC_CONFIG_FILES([ Makefile ])

AC_OUTPUT
