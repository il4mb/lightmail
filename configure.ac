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
])

AC_CONFIG_FILES([ Makefile ])

AC_OUTPUT
