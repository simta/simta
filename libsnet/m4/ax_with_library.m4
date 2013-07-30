AC_DEFUN([AX_WITH_LIBRARY],
[
    AC_ARG_WITH($1, AC_HELP_STRING([--with-$1=DIR], [$1 installation directory]))

    AC_MSG_CHECKING([for $1])

    AS_IF(
        [test "x$with_]$1[" != "xno"],
        [AX_CHECK_LIBRARY($2, $3, $4,
            [AC_MSG_RESULT([yes])
             EXTRALIBS="-l$4 $5 $EXTRALIBS"
             CONFIG_DEFINES="$CONFIG_DEFINES
#ifndef ${CONFIG_PREFIX}HAVE_$2
#define ${CONFIG_PREFIX}HAVE_$2
#endif"
             ], 
            [AC_MSG_RESULT([no])]
        )],
        [AC_MSG_RESULT([disabled])]
    )
])
