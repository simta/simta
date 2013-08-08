# Process this file with autoconf to produce a configure script.

AC_INIT(simta, m4_esyscmd([bash version.sh]), simta@umich.edu)

AC_PREREQ(2.63)
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) 1998 Regents of The University of Michigan])
AC_CONFIG_AUX_DIR([libsnet])

# Set up local variables
AC_ARG_WITH(aliasdb, AC_HELP_STRING([--with-alias-db=DB], [default alias db]), [], with_aliasdb="/etc/alias.db" )
AC_DEFINE_UNQUOTED(SIMTA_ALIAS_DB, ["$with_aliasdb"], [default alias db location])

AC_ARG_WITH(logfacility, AC_HELP_STRING([--with-log-facility=facility], [syslog facility]), [], with_logfacility="LOG_MAIL")
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

# Check for files
AC_STRUCT_TIMEZONE

# Find local mailers
SET_LOCALDELIVERY
PROG_MAIL_LOCAL
PROG_PROCMAIL
WARN_LOCALDELIVERY

if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

AC_STRUCT_TM
AC_STRUCT_GMTOFF

AC_SUBST(SRC, [])
AC_SUBST(SIMTA_OBJ, [])
AC_SUBST(SIMSEND_OBJ, [])
AC_SUBST(SIMC_OBJ, [])
AC_SUBST(Q_RUNNER_OBJ, [])
AC_SUBST(EXPANDER_OBJ, [])
AC_SUBST(EXTRALIBS, [])

# Check for libraries
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([crypt], [crypt])

AX_PATH_BDB([4], [
    AC_DEFINE([HAVE_DB], [1], [Define if BDB exists.])
    EXTRALIBS="$BDB_LIBS $EXTRALIBS"
    AC_SUBST(BDB_LDFLAGS)
    AC_SUBST(BDB_CPPFLAGS)
])

AX_WITH_LIBRARY([ssl], [LIBSSL], [openssl/ssl.h], [ssl], [-lcrypto])
AX_WITH_LIBRARY([ldap], [LDAP], [ldap.h], [ldap], [-llber])
AX_WITH_LIBRARY([libwrap], [LIBWRAP], [tcpd.h], [wrap])
AX_WITH_LIBRARY([sasl2], [LIBSASL], [sasl/sasl.h], [sasl2])
AX_WITH_LIBRARY([zlib], [ZLIB], [zlib.h], [z])

# Is this really where we should put this?
if test x"$ax_cv_have_LDAP" = xyes; then
    SRC="$SRC simta_ldap.c dn.c"
    SIMTA_OBJ="$SIMTA_OBJ simta_ldap.o dn.o"
    SIMSEND_OBJ="$SIMSEND_OBJ simta_ldap.o dn.o"
    SIMC_OBJ="$SIMC_OBJ simta_ldap.o dn.o"
    Q_RUNNER_OBJ="$Q_RUNNER_OBJ simta_ldap.o dn.o"
    EXPANDER_OBJ="$EXPANDER_OBJ simta_ldap.o dn.o"
fi

if test "x$srcdir" = x.; then
extrasub="$extrasub
/^srcdir=/d
/^SRCPFX/d"
fi

AC_CONFIG_SUBDIRS(libsnet)
AC_CONFIG_SUBDIRS(denser)

AC_CONFIG_FILES([ Makefile ])
AC_OUTPUT
