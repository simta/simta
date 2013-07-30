# Process this file with autoconf to produce a configure script.
AC_INIT(libsnet, 1.0.0, rsug@umich.edu) 
AM_INIT_AUTOMAKE([foreign])
AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright (c) 1995-2003 Regents of The University of Michigan.  All Rights Reserved.])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR([snet.c])
AC_CONFIG_MACRO_DIR([m4])

# Canonicalise things
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
CONFIG_PREFIX="SNET_"
AX_WITH_LIBRARY([zlib], [ZLIB], [zlib.h], [z])
AX_WITH_LIBRARY([ssl], [LIBSSL], [openssl/ssl.h], [ssl], [-lcrypto])
AX_WITH_LIBRARY([sasl2], [LIBSASL], [sasl/sasl.h], [sasl2])

AC_SUBST([CONFIG_DEFINES])
AM_SUBST_NOTMAKE([CONFIG_DEFINES])

LIBS="$EXTRALIBS $LIBS"

CHECK_UNIVERSAL_BINARIES
MACOSX_MUTE_DEPRECATION_WARNINGS

# Checks for header files.
#AC_HEADER_STDC
#AC_CHECK_HEADERS([fcntl.h inttypes.h netinet/in.h stdlib.h string.h sys/param.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
#AC_HEADER_TIME

# Checks for library functions.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_CHECK_FUNCS([gettimeofday select])

# Checks for how to build libraries
CHECK_PROFILED
AC_DISABLE_SHARED
AC_PROG_LIBTOOL  # Checks whether to build shared and/or static libraries

# Miscellaneous:
if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

# Write output:
AC_CONFIG_FILES([Makefile snet.h])
AC_OUTPUT
