AC_DEFUN([CHECK_SSL],
[
    AC_MSG_CHECKING(for ssl)
    ssldirs="/usr/local/openssl /usr/lib/openssl /usr/openssl \
	    /usr/local/ssl /usr/lib/ssl /usr/ssl \
	    /usr/pkg /usr/local /usr"
    AC_ARG_WITH(ssl,
	    AC_HELP_STRING([--with-ssl=DIR], [path to ssl]),
	    ssldirs="$withval")
    for dir in $ssldirs; do
	ssldir="$dir"
	if test -f "$dir/include/openssl/ssl.h"; then
	    found_ssl="yes";
	    CPPFLAGS="$CPPFLAGS -I$ssldir/include";
	    break;
	fi
	if test -f "$dir/include/ssl.h"; then
	    found_ssl="yes";
	    CPPFLAGS="$CPPFLAGS -I$ssldir/include";
	    break
	fi
    done
    if test x_$found_ssl != x_yes; then
	AC_MSG_ERROR(cannot find ssl libraries)
    else
	TLSDEFS=-DTLS;
	AC_SUBST(TLSDEFS)
	LIBS="$LIBS -lssl -lcrypto";
	LDFLAGS="$LDFLAGS -L$ssldir/lib";
	HAVE_SSL=yes
    fi
    AC_SUBST(HAVE_SSL)
    AC_MSG_RESULT(yes)
])


AC_DEFUN([CHECK_SNET],
[
    AC_MSG_CHECKING(for snet)
    snetdir="libsnet"
    AC_ARG_WITH(snet,
	    AC_HELP_STRING([--with-snet=DIR], [path to snet]),
	    snetdir="$withval")
    if test -f "$snetdir/snet.h"; then
	found_snet="yes";
	CPPFLAGS="$CPPFLAGS -I$snetdir";
    fi
    if test x_$found_snet != x_yes; then
	AC_MSG_ERROR(cannot find snet libraries)
    else
	LIBS="$LIBS -lsnet";
	LDFLAGS="$LDFLAGS -L$snetdir";
	HAVE_SNET=yes
    fi
    AC_SUBST(HAVE_SNET)
    AC_MSG_RESULT(yes)
])


# AC_STRUCT_GMTOFF
# If struct tm contains tm_gmtoff, define HAVE_TM_GMTOFF.
#
# AC_STRUCT_TM defines $ac_cv_struct_tm to the library where struct
# tm resides.

AC_DEFUN([AC_STRUCT_GMTOFF],
[
    AC_REQUIRE([AC_STRUCT_TM])
    AC_MSG_CHECKING([for tm_gmtoff in struct tm])
    AC_CACHE_VAL(ac_cv_struct_gmtoff,
	[ AC_TRY_COMPILE([#include <$ac_cv_struct_tm>],
	    [struct tm tm; tm.tm_gmtoff;],
	    ac_cv_struct_gmtoff=yes, ac_cv_struct_gmtoff=no)])
    AC_MSG_RESULT($ac_cv_struct_gmtoff)
    AC_SUBST(HAVE_TM_GMTOFF, "")
    if test $ac_cv_struct_gmtoff = yes; then
	HAVE_TM_GMTOFF="-DHAVE_TM_GMTOFF";
    fi
])
