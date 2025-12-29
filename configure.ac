AC_INIT([lightmail], [0.1], [durianbohong@gmail.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/lightmail.c])


AC_PROG_CC
LT_INIT

AC_CHECK_HEADERS([
    mysql/mysql.h
    openssl/evp.h,
    openssl/rand.h,

    syslog.h
    unistd.h
    stdlib.h
    string.h
])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT
