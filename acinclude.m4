m4_include([m4/ax_check_library.m4])  
m4_include([m4/ax_with_library.m4])  

AC_DEFUN([SET_LOCALDELIVERY],
[
    have_local_delivery="no"
])


AC_DEFUN([WARN_LOCALDELIVERY],
[
    if test x_$have_local_delivery != x_yes; then
	AC_MSG_WARN([simta requires a local mailer: see INSTALL])
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
	    PROCMAIL="$dir/procmail"
	fi

    else
	AC_MSG_RESULT(disabled);
    fi
    AC_DEFINE_UNQUOTED(SIMTA_PROCMAIL, ["$PROCMAIL"], [path to procmail])
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
            MAIL_LOCAL="$dir/mail.local"
	fi

    else
	AC_MSG_RESULT(disabled);
    fi
    AC_DEFINE_UNQUOTED(SIMTA_MAIL_LOCAL, ["$MAIL_LOCAL"], [path to mail.local])
])
