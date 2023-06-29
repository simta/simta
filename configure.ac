# Process this file with autoconf to produce a configure script.

AC_INIT(simta, m4_esyscmd([sh version.sh]), simta@umich.edu)
AM_INIT_AUTOMAKE([foreign subdir-objects no-dist-gzip dist-xz])

AC_PREREQ(2.63)
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) 1998-2019 Regents of The University of Michigan])

# Set up local variables
AC_ARG_WITH(logfacility, AC_HELP_STRING([--with-logfacility=facility], [syslog facility]), [], with_logfacility="LOG_MAIL")
AC_DEFINE_UNQUOTED(LOG_SIMTA, [$with_logfacility], [syslog facility])

AC_ARG_ENABLE(chown, AC_HELP_STRING([--disable-chown], [do not set ownership of setuid binaries during installation]), [], enable_chown="yes")

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LN_S

AC_USE_SYSTEM_EXTENSIONS

# Checks for functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MKTIME

AC_SUBST(EXTRALIBS, [])
AC_SUBST(JEMALLOC_CFLAGS, [])
AC_SUBST(JEMALLOC_LIBS, [])
AC_SUBST(LDAP_SRC, [])
AC_SUBST(LMDB_SRC, [])
AC_SUBST(SSL_SRC, [])

# Check for libraries
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([crypt], [crypt])

# Required packages
PKG_CHECK_MODULES([DENSER], [denser >= 0.5.2])
PKG_CHECK_MODULES([SNET], [libsnet])
PKG_CHECK_MODULES([LIBUCL], [libucl >= 0.8.1])

# Optional packages
AC_ARG_WITH([dkim], AC_HELP_STRING([--with-dkim], [Build with DKIM support]))
AS_IF(
    [test "x$with_dkim" != "xno"],
    [PKG_CHECK_MODULES([OPENDKIM], [opendkim],  [AC_DEFINE([HAVE_LIBOPENDKIM], [1], [Define to 1 if OPENDKIM is available])])])

AC_ARG_WITH([arc], AC_HELP_STRING([--with-arc], [Build with ARC support]))
AS_IF(
    [test "x$with_arc" = "xyes"],
    [PKG_CHECK_MODULES([OPENARC], [openarc],  [AC_DEFINE([HAVE_LIBOPENARC], [1], [Define to 1 if OPENARC is available])])])

AC_ARG_WITH([sasl], AC_HELP_STRING([--with-sasl], [Build with SASL support]))
AS_IF(
    [test "x$with_sasl" != "xno"],
    [PKG_CHECK_MODULES([LIBSASL], [libsasl2], [AC_DEFINE([HAVE_LIBSASL], [1], [Define to 1 if LIBSASL is found])])])

AC_ARG_WITH([ssl], AC_HELP_STRING([--with-ssl], [Build with TLS support]))
AS_IF(
    [test "x$with_ssl" != "xno"],
    [PKG_CHECK_MODULES([LIBSSL], [openssl], [AC_DEFINE([HAVE_LIBSSL], [1], [Define to 1 if LIBSSL is found])])])

AC_ARG_WITH([libidn2], AC_HELP_STRING([--with-libidn2], [Build with IDNA support]))
AS_IF(
    [test "x$with_libidn2" != "xno"],
    [PKG_CHECK_MODULES([LIBIDN2], [libidn2],  [AC_DEFINE([HAVE_LIBIDN2], [1], [Define to 1 if LIBIDN2 is available])])])

AC_ARG_WITH([jemalloc], AC_HELP_STRING([--with-jemalloc], [Use the jemalloc allocator]))
AS_IF(
    [test "x$with_jemalloc" != "xno"],
    [PKG_CHECK_MODULES([JEMALLOC], [jemalloc], [AC_DEFINE([HAVE_JEMALLOC], [1], [Define to 1 if JEMALLOC is available])])])

AC_ARG_WITH([cmocka], AC_HELP_STRING([--with-cmocka], [Build unit tests]))
AS_IF(
    [test "x$with_cmocka" = "xyes"],
    [PKG_CHECK_MODULES([CMOCKA], [cmocka], [AC_DEFINE([HAVE_CMOCKA], [1], [Define to 1 if CMOCKA is available])])])

# Packages without pkgconfig files
AX_WITH_LIBRARY([ldap], [LDAP], [ldap.h], [ldap], [-llber])
AX_WITH_LIBRARY([libwrap], [LIBWRAP], [tcpd.h], [wrap])
AX_WITH_LIBRARY([lmdb], [LMDB], [lmdb.h], [lmdb])

AM_CONDITIONAL(BUILD_CMOCKA, [test x"$with_cmocka" = xyes])
AM_CONDITIONAL(BUILD_LDAP, [test x"$ax_cv_have_LDAP" = xyes])
AM_CONDITIONAL(BUILD_LMDB, [test x"$ax_cv_have_LMDB" = xyes])
AM_CONDITIONAL(BUILD_SASL, [test x"$with_sasl" != xno])
AM_CONDITIONAL(BUILD_SSL, [test x"$with_ssl" != xno])
AM_CONDITIONAL(CHOWN_FILES, [test "x$enable_chown" = "xyes"])

AC_CONFIG_FILES([ Makefile test/Makefile packaging/rpm/simta.spec ])
AC_OUTPUT
