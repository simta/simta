# Process this file with autoconf to produce a configure script.

AC_INIT(simta, VERSION, simta@umich.edu)
AC_PREREQ(2.52)
AC_CONFIG_HEADER(config.h)
AC_COPYRIGHT([Copyright (c) 1998 Regents of The University of Michigan])
AC_CONFIG_AUX_DIR([libsnet])

# Setup local variables
AC_ARG_WITH(resolvconf, AC_HELP_STRING([--with-resolv=RESOLV], [default resolv.conf]), resolvconf="$withval", resolvconf="/etc/resolv.conf" )
AC_SUBST(resolvconf)

AC_ARG_WITH(aliasdb, AC_HELP_STRING([--with-alias-db=DB], [default alias db]), aliasdb="$withval", aliasdb="/etc/alias.db" )
AC_SUBST(aliasdb)

AC_ARG_WITH(maxconnections, AC_HELP_STRING([--with-maxconnections=MAX], [maximum number of client connections]), maxconnections="$withval", maxconnections=0 )
AC_SUBST(maxconnections)

# Local Stuff
AC_PREFIX_DEFAULT(/usr/local)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Check for files
AC_CHECK_FILE($resolvconf,,AC_MSG_ERROR(No valid resolv.conf)) 
AC_STRUCT_TIMEZONE

# Find local mailers
SET_LOCALDELIVERY
PROG_MAIL_LOCAL
PROG_PROCMAIL
CHECK_LOCALDELIVERY

if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes -Wconversion"}
fi
AC_SUBST(OPTOPTS)

AC_STRUCT_TM
AC_STRUCT_GMTOFF

CHECK_DB

AC_CHECK_LIB([ldap], [ldap_init], , [CHECK_LDAP])
AC_CHECK_LIB([ssl], [SSL_accept], , [CHECK_SSL])
AC_CHECK_LIB([crypto], [SSLeay_version], , [CHECK_SSL])
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])

AC_CONFIG_SUBDIRS(libsnet)
AC_CONFIG_SUBDIRS(denser)

AC_CONFIG_FILES([ Makefile ])
AC_OUTPUT
