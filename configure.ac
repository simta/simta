# Process this file with autoconf to produce a configure script.

AC_INIT(simta, VERSION, simta@umich.edu)
AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright (c) 1998 Regents of The University of Michigan])
AC_CONFIG_AUX_DIR([libsnet])

# Local Stuff
AC_PREFIX_DEFAULT(/usr/local)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes -Wconversion"}
fi
AC_SUBST(OPTOPTS)

AC_STRUCT_TM
AC_STRUCT_GMTOFF

CHECK_SSL

AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])

AC_CONFIG_SUBDIRS(libsnet)
AC_CONFIG_SUBDIRS(denser)

AC_CONFIG_FILES([ Makefile ])
AC_OUTPUT
