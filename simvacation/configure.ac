#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_CONFIG_SRCDIR([simunvacation.c])
## AC_CONFIG_HEADER([config.h])

# Set up variables
AC_ARG_WITH(vacationdb, AC_HELP_STRING([--with-vacationdb=vacationdb], [default: /var/vacationdb]), vacationdb="$withval", vacationdb="/var/vacationdb")
AC_SUBST(vacationdb)

AC_ARG_WITH(syslog, AC_HELP_STRING([--with-syslog=LOG_MAIL], [default syslog facility: LOG_MAIL]), vacsyslog="$withval", vacsyslog="LOG_MAIL")
AC_SUBST(vacsyslog)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
CHECK_LDAP
CHECK_DB

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h strings.h sys/param.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_FORK
AC_CHECK_FUNCS([dup2 memset strcasecmp strdup strerror strncasecmp strrchr])

if test "x$srcdir" = x.; then
extrasub="$extrasub
/^srcdir=/d
/^SRCPFX/d"
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
