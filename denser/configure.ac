# Process this file with autoconf to produce a configure script.
AC_INIT(denser, VERSION, denser@umich.edu)
AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright (c) 2003 Regents of The University of Michigan.  All Rights Reserved.])
AC_CONFIG_SRCDIR([dense.c])

# Checks for programs.
AC_PROG_CC

# Check host
AC_C_BIGENDIAN( ENDIAN="-DENDIAN_BIG", ENDIAN="-DENDIAN_LITTLE" )
AC_SUBST(ENDIAN)

# Miscellaneous:
if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

AC_ARG_WITH(resolv_conf_path, AC_HELP_STRING([--with-resolvconf=PATH], [default resolv.conf path]), resolv_conf_path="$withval", resolv_conf_path="/etc/resolv.conf" )
AC_SUBST(resolv_conf_path)


# Checks for libraries.
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])

if test "x$srcdir" = x.; then
extrasub="$extrasub
/^srcdir=/d
/^SRCPFX/d"
fi

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
