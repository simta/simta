AC_DEFUN([CHECK_LDAP],
[
    AC_MSG_CHECKING(for ldap)

    ldapdirs="yes"

    AC_ARG_WITH(ldap,
	    AC_HELP_STRING([--with-ldap=DIR], [path to ldap]),
	    ldapdirs="$withval")

    # ldapdirs will be "yes", "no", or a user defined path
    if test x_$ldapdirs != x_no; then
	if test x_$ldapdirs = x_yes; then
	    ldapdirs="/usr/local /usr/local/ldap /usr/local/openldap"
	fi

	for dir in $ldapdirs; do
	    ldapdir="$dir"
	    if test -f "$dir/include/ldap.h"; then
		found_ldap="yes";
		AC_MSG_RESULT(yes)
		break
	    fi
	done

	if test x_$found_ldap != x_yes; then
	    AC_MSG_RESULT(no)
	else
	    LIBS="$LIBS -lldap -llber";
	    CFLAGS="$CFLAGS -I$ldapdir/include";
	    LDFLAGS="$LDFLAGS -L$ldapdir/lib";
	    TEST_SRC="$TEST_SRC ldap.c"
	    TEST_OBJ="$TEST_OBJ ldap.o"
	    AC_DEFINE(HAVE_LDAP)
	fi

    else
	AC_MSG_RESULT(disabled)

    fi
])


AC_DEFUN([CHECK_LIBKRB],
[
    AC_MSG_CHECKING(for libkrb)

    libkrbdirs="no"

    AC_ARG_WITH(libkrb,
	    AC_HELP_STRING([--with-libkrb=DIR], [path to libkrb]),
	    libkrbdirs="$withval")

    if test x_$libkrbdirs != x_no; then
	if test x_$libkrbdirs = x_yes; then
	    libkrbdirs="/usr/lib /usr/local/lib"
	fi

	for dir in $libkrbdirs; do
	    libkrbdir="$dir"
	    if test -f "$dir/libkrb.a"; then
		found_libkrb="yes";
		AC_MSG_RESULT(yes)
		LIBS="$LIBS -lkrb";
		break
	    fi
	done

	if test x_$found_libkrb != x_yes; then
	    AC_MSG_RESULT(no)
	    AC_MSG_CHECKING(for libkrb5)
	    for dir in $libkrbdirs; do
		libkrbdir="$dir"
		if test -f "$dir/libkrb5.a"; then
		    found_libkrb="yes";
		    AC_MSG_RESULT(yes)
		    LIBS="$LIBS -lkrb5";
		    break
		fi
	    done
	fi

	if test x_$found_libkrb != x_yes; then
	    AC_MSG_RESULT(no)
	    AC_MSG_CHECKING(for libkrb4)
	    for dir in $libkrbdirs; do
		libkrbdir="$dir"
		if test -f "$dir/libkrb4.a"; then
		    found_libkrb="yes";
		    AC_MSG_RESULT(yes)
		    LIBS="$LIBS -lkrb4";
		    break
		fi
	    done
	fi

	if test x_$found_libkrb != x_yes; then
	    AC_MSG_RESULT(no)
	fi

    else
	AC_MSG_RESULT(not enabled)

    fi
])


AC_DEFUN([PROG_SENDMAIL],
[
    AC_MSG_CHECKING(for sendmail)
    sendmaildirs="/usr/lib /usr/sbin"
    AC_ARG_WITH(sendmail,
	    AC_HELP_STRING([--with-sendmail=DIR], [path to sendmail]),
	    sendmaildirs="$withval")
    for dir in $sendmaildirs; do
	sendmaildir="$dir"
	if test -f "$dir/sendmail"; then
	    found_sendmail="yes";
	    break
	fi
    done
    if test x_$found_sendmail != x_yes; then
	AC_MSG_ERROR([not found: See INSTALL])
    else
	AC_SUBST( NEFU_SENDMAIL, [$dir/sendmail])
	AC_MSG_RESULT(yes)
    fi
])


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
