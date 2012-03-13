AC_DEFUN([CHECK_LDAP],
[
    AC_MSG_CHECKING(for ldap)
    # XXX Get all the directories ldap could live
    ldapdirs="/usr/local /usr/local/ldap /usr/local/openldap"
    AC_ARG_WITH(ldap,
	    AC_HELP_STRING([--with-ldap=DIR], [path to ldap]),
	    ldapdirs="$withval")
    for dir in $ldapdirs; do
	ldapdir="$dir"
	if test -f "$dir/include/ldap.h"; then
	    found_ldap="yes";
	    break
	fi
    done
    if test x_$found_ldap == x_yes; then
	CFLAGS="$CFLAGS -I$ldapdir/include";
	LIBS="$LIBS -lldap -llber";
	LDFLAGS="$LDFLAGS -L$ldapdir/lib";
	AC_DEFINE(HAVE_LDAP)
	AC_MSG_RESULT(yes)
        
    else
	if test -f "/usr/include/ldap.h"; then
	    found_ldap="yes";
	    LIBS="$LIBS -lldap -llber";
	    AC_DEFINE(HAVE_LDAP)
	    AC_MSG_RESULT(yes)
	else
	    AC_MSG_RESULT(no)
	fi
    fi
])

AC_DEFUN([CHECK_DB],
[
    AC_MSG_CHECKING(for db)
    dbdirs="/usr/local/db /usr/db /usr/local/BerkeleyDB.4.2\
            /usr/pkg /usr/local /usr"
    AC_ARG_WITH(db,
            AC_HELP_STRING([--with-db=DIR], [path to db]),
            dbdirs="$withval")
    for dir in $dbdirs; do
        dbdir="$dir"
        if test -f "$dir/lib/libdb.a"; then
            found_db="yes";
            CFLAGS="-I$dbdir/include";
            break;
        fi
    done
    if test x_$found_db != x_yes; then
        AC_MSG_ERROR(cannot find db )
    else
	LDFLAGS="-L$dbdir/lib -Wl,-rpath -Wl,$dbdir/lib $LDFLAGS";
	LIBS="$LIBS -ldb";
	AC_DEFINE(HAVE_DB)
	AC_MSG_RESULT(yes)
        HAVE_DB=yes
    fi
    AC_SUBST(HAVE_DB)
    AC_MSG_RESULT(yes)
])

