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
	    CPPFLAGS="$CPPFLAGS -I$ssldir/include/openssl";
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
# If struct tm.tm_gmtoff exists, define HAVE_TM_GMTOFF.
#
# AC_STRUCT_TM defines $ac_cv_struct_tm to the library where struct
# tm resides.

AC_DEFUN([AC_STRUCT_GMTOFF],
[
    AC_REQUIRE([AC_STRUCT_TM])
    AC_MSG_CHECKING([for struct tm.tm_gmtoff in $ac_cv_struct_tm])
    AC_TRY_COMPILE([#include <$ac_cv_struct_tm>],
	    [struct tm tm; tm.tm_gmtoff;],
	    ac_cv_struct_gmtoff=yes, ac_cv_struct_gmtoff=no)
    AC_MSG_RESULT($ac_cv_struct_gmtoff)
    AC_SUBST(HAVE_TM_GMTOFF, "")
    if test $ac_cv_struct_gmtoff = yes; then
	HAVE_TM_GMTOFF="-DHAVE_TM_GMTOFF";
    fi
])


AC_DEFUN([SET_LOCALDELIVERY],
[
    have_local_delivery="no"
])


AC_DEFUN([CHECK_LOCALDELIVERY],
[
    if test x_$have_local_delivery != x_yes; then
	AC_MSG_ERROR([simta requires a local mailer: see INSTALL])
    fi
])


AC_DEFUN([PROG_PROCMAIL],
[
    AC_MSG_CHECKING(for procmail)
    procmail_dirs="yes"
    AC_ARG_WITH(procmail,
	    AC_HELP_STRING([--with-procmail=DIR], [path to procmail]),
	    procmail_dirs="$withval")

    # procmail_dirs will be "yes", "no", or a user defined path
    if test x_$procmail_dirs != x_no; then
	if test x_$procmail_dirs = x_yes; then
	    procmail_dirs="/usr/bin /usr/local/bin /usr/local/procmail/bin"
	fi
	for dir in $procmail_dirs; do
	    procmail_dir="$dir"
	    if test -f "$dir/procmail"; then
		found_procmail="yes";
		have_local_delivery="yes";
		AC_MSG_RESULT(yes)
		break
	    fi
	done
	if test x_$found_procmail != x_yes; then
	    AC_MSG_RESULT(no)
	else
	    AC_SUBST( SIMTA_PROCMAIL, [$dir/procmail])
	fi

    else
	AC_MSG_RESULT(disabled);
    fi
])


AC_DEFUN([PROG_MAIL_LOCAL],
[
    AC_MSG_CHECKING(for mail.local)
    mail_local_dirs="yes"
    AC_ARG_WITH(mail_local,
	    AC_HELP_STRING([--with-mail_local=DIR], [path to mail.local]),
	    mail_local_dirs="$withval")

    # mail_local_dirs will be "yes", "no", or a user defined path
    if test x_$mail_local_dirs != x_no; then
	if test x_$mail_local_dirs = x_yes; then
	    mail_local_dirs="/usr/lib /usr/sbin"
	fi
	for dir in $mail_local_dirs; do
	    mail_local_dir="$dir"
	    if test -f "$dir/mail.local"; then
		found_mail_local="yes";
		have_local_delivery="yes";
		AC_MSG_RESULT(yes)
		break
	    fi
	done
	if test x_$found_mail_local != x_yes; then
	    AC_MSG_RESULT(no)
	else
	    AC_SUBST( SIMTA_MAIL_LOCAL, [$dir/mail.local])
	fi

    else
	AC_MSG_RESULT(disabled);
    fi
])

AC_DEFUN([CHECK_DB],
[
    AC_MSG_CHECKING(for db)
    dbdirs="/usr/local/db /usr/db \
            /usr/pkg /usr/local /usr /usr/local/BerkeleyDB"
    AC_ARG_WITH(db,
            AC_HELP_STRING([--with-db=DIR], [path to db]),
            dbdirs="$withval")
    for dir in $dbdirs; do
        dbdir="$dir"
        if test -f "$dir/lib/libdb.a"; then
            found_db="yes";
            SIMTACPPFLAGS="-I$dbdir/include";
            break;
        fi
    done
    if test x_$found_db != x_yes; then
        AC_MSG_ERROR(cannot find db )
    else
        SIMTALIBS="-ldb";
        SIMTALDFLAGS="-L$dbdir/lib -R$dbdir/lib";
	AC_SUBST(SIMTALIBS)
	AC_SUBST(SIMTALDFLAGS)
	AC_SUBST(SIMTACPPFLAGS)
        HAVE_DB=yes
    fi
    AC_SUBST(HAVE_DB)
    AC_MSG_RESULT(yes)
])
