# Process this file with autoconf to produce a configure script.

AC_INIT(simta, m4_esyscmd([bash version.sh]), simta@umich.edu)

AC_PREREQ(2.52)
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) 1998 Regents of The University of Michigan])
AC_CONFIG_AUX_DIR([libsnet])

# Set up local variables
AC_ARG_WITH(aliasdb, AC_HELP_STRING([--with-aliasdb=DB], [default alias db]), [], with_aliasdb="/etc/alias.db" )
AC_DEFINE_UNQUOTED(SIMTA_ALIAS_DB, ["$with_aliasdb"], [default alias db location])

AC_ARG_WITH(logfacility, AC_HELP_STRING([--with-logfacility=facility], [syslog facility]), [], with_logfacility="LOG_MAIL")
AC_DEFINE_UNQUOTED(LOG_SIMTA, [$with_logfacility], [syslog facility])

AC_ARG_WITH(maxconnections, AC_HELP_STRING([--with-maxconnections=MAX], [maximum number of client connections]), [], with_maxconnections=0 )
AC_DEFINE_UNQUOTED(SIMTA_MAXCONNECTIONS, [$with_maxconnections], [default maximum number of client connections])

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

AX_PATH_BDB([4],[
    SIMTALIBS="$SIMTALIBS $BDB_LIBS"
    SIMTALDFLAGS="$SIMTALDFLAGS $BDB_LDFLAGS"
    SIMTACPPFLAGS="$SIMTACPPFLAGS $BDB_CPPFLAGS"
    HAVE_DB=yes
])

AC_SUBST(SIMTALIBS)
AC_SUBST(SIMTALDFLAGS)
AC_SUBST(SIMTACPPFLAGS)
AC_SUBST(HAVE_DB)

CHECK_LDAP
CHECK_LIBWRAP
CHECK_SASL

#AC_CHECK_LIB([ldap], [ldap_init], , [CHECK_LDAP])
AC_CHECK_LIB([ssl], [SSL_accept], , [CHECK_SSL])
AC_CHECK_LIB([crypto], [SSLeay_version], , [CHECK_SSL])
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([crypt], [crypt])

if test "x$srcdir" = x.; then
extrasub="$extrasub
/^srcdir=/d
/^SRCPFX/d"
fi

AC_CONFIG_SUBDIRS(libsnet)
AC_CONFIG_SUBDIRS(denser)

AC_CONFIG_FILES([ Makefile ])
AC_OUTPUT
