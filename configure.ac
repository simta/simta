# Process this file with autoconf to produce a configure script.

AC_INIT(simta, m4_esyscmd([sh version.sh]), simta@umich.edu)

AC_PREREQ(2.63)
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) 1998-2015 Regents of The University of Michigan])

# Set up local variables
AC_ARG_WITH(aliasdb, AC_HELP_STRING([--with-aliasdb=DB], [default alias db]), [], with_aliasdb="/etc/alias.db" )
AC_DEFINE_UNQUOTED(SIMTA_ALIAS_DB, ["$with_aliasdb"], [default alias db location])

AC_ARG_WITH(logfacility, AC_HELP_STRING([--with-logfacility=facility], [syslog facility]), [], with_logfacility="LOG_MAIL")
AC_DEFINE_UNQUOTED(LOG_SIMTA, [$with_logfacility], [syslog facility])

AC_ARG_WITH(maxconnections, AC_HELP_STRING([--with-maxconnections=MAX], [maximum number of client connections]), [], with_maxconnections=0 )
AC_DEFINE_UNQUOTED(SIMTA_MAXCONNECTIONS, [$with_maxconnections], [default maximum number of client connections])

AC_ARG_ENABLE(chown, AC_HELP_STRING([--disable-chown], [do not set ownership of setuid binaries during installation]), [], enable_chown="yes")
AS_IF([test "x$enable_chown" = "xyes"], [AC_SUBST(SUID_OWNER, "-o simta -g simta")], [AC_SUBST(SUID_OWNER, "")])

# Local Stuff
AC_PREFIX_DEFAULT(/usr/local)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC

# Find local mailers
SET_LOCALDELIVERY
PROG_MAIL_LOCAL
PROG_PROCMAIL
WARN_LOCALDELIVERY

if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

AC_SUBST(EXTRALIBS, [])
AC_SUBST(JEMALLOC_CFLAGS, [])
AC_SUBST(JEMALLOC_LIBS, [])
AC_SUBST(LDAP_SRC, [])
AC_SUBST(LDAP_OBJ, [])
AC_SUBST(LMDB_SRC, [])
AC_SUBST(LMDB_OBJ, [])
AC_SUBST(SSL_SRC, [])
AC_SUBST(SSL_OBJ, [])

# Check for libraries
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([crypt], [crypt])

# Required packages
PKG_CHECK_MODULES([DENSER], [denser])
PKG_CHECK_MODULES([SNET], [libsnet])
PKG_CHECK_MODULES([YASL], [libyasl])

# Optional packages
AC_ARG_WITH([sasl], AC_HELP_STRING([--with-sasl], [Build with SASL support]))
AS_IF(
    [test "x$with_sasl" != "xno"],
    [PKG_CHECK_MODULES([LIBSASL], [libsasl2], [AC_DEFINE([HAVE_LIBSASL], [1], [Define to 1 if LIBSASL is found])])])

AC_ARG_WITH([ssl], AC_HELP_STRING([--with-ssl], [Build with TLS support]))
AS_IF(
    [test "x$with_ssl" != "xno"],
    [PKG_CHECK_MODULES([LIBSSL], [openssl], [AC_DEFINE([HAVE_LIBSSL], [1], [Define to 1 if LIBSSL is found])])])

AC_ARG_WITH([jemalloc], AC_HELP_STRING([--with-jemalloc], [Use the jemalloc allocator]))
AS_IF(
    [test "x$with_jemalloc" != "xno"],
    [PKG_CHECK_MODULES([JEMALLOC], [jemalloc], [AC_DEFINE([HAVE_JEMALLOC], [1], [Define to 1 if JEMALLOC is available])])])

# Packages without pkgconfig files
AX_WITH_LIBRARY([ldap], [LDAP], [ldap.h], [ldap], [-llber])
AX_WITH_LIBRARY([libwrap], [LIBWRAP], [tcpd.h], [wrap])
AX_WITH_LIBRARY([lmdb], [LMDB], [lmdb.h], [lmdb])

if test x"$ax_cv_have_LDAP" = xyes; then
    LDAP_SRC="simta_ldap.c dn.c"
    LDAP_OBJ="simta_ldap.o dn.o"
fi

if test x"$ax_cv_have_LMDB" = xyes; then
    LMDB_SRC="simta_lmdb.c"
    LMDB_OBJ="simta_lmdb.o"
fi

if test x"$with_ssl" != xno; then
    SSL_SRC="md.c tls.c"
    SSL_OBJ="md.o tls.o"
fi

AC_CONFIG_FILES([ Makefile packaging/rpm/simta.spec ])
AC_OUTPUT
