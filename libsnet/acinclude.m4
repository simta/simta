AC_DEFUN([CHECK_PROFILED],
[
    # Allow user to control whether or not profiled libraries are built
    AC_MSG_CHECKING(whether to build profiled libraries)
    PROFILED=true
    AC_ARG_ENABLE(profiled,
      [  --enable-profiled       build profiled libsnet (default=yes)],
      [test x_$enable_profiled = x_no && PROFILED=false]
    )
    AC_SUBST(PROFILED)
    if test x_$PROFILED = x_true ; then
      AC_MSG_RESULT(yes)
    else
      AC_MSG_RESULT(no)
    fi
])

AC_DEFUN([CHECK_UNIVERSAL_BINARIES],
[
    AC_ARG_ENABLE(universal_binaries,
	AC_HELP_STRING([--enable-universal_binaries], [build universal binaries (default=no)]),
	,[enable_universal_binaries=no])
    if test "${enable_universal_binaries}" = "yes"; then
	case "${host_os}" in
	  darwin8*)
	    macosx_sdk="MacOSX10.4u.sdk"
	    arches="-arch i386 -arch ppc"
	    ;;

	  darwin9*)
	    dep_target="-mmacosx-version-min=10.4"
	    macosx_sdk="MacOSX10.5.sdk"
	    arches="-arch i386 -arch x86_64 -arch ppc -arch ppc64"
	    ;;

	  darwin10*)
	    dep_target="-mmacosx-version-min=10.4"
	    macosx_sdk="MacOSX10.6.sdk"
	    arches="-arch i386 -arch x86_64 -arch ppc"
	    ;;
	
	  *)
	    AC_MSG_ERROR([Building universal binaries on ${host_os} is not supported])
	    ;;
	  esac
	echo ===========================================================
	echo Setting up universal binaries for ${host_os}
	echo ===========================================================
	OPTOPTS="$OPTOPTS -isysroot /Developer/SDKs/$macosx_sdk $dep_target $arches"
    fi
])

AC_DEFUN([MACOSX_MUTE_DEPRECATION_WARNINGS],
[
    dnl Lion deprecates a system-provided OpenSSL. Build output
    dnl is cluttered with useless deprecation warnings.

    AS_IF([test x"$CC" = x"gcc"], [
        case "${host_os}" in
        darwin11*)
            AC_MSG_NOTICE([muting deprecation warnings from compiler])
            OPTOPTS="$OPTOPTS -Wno-deprecated-declarations"
            ;;

        *)
            ;;
        esac
    ])
])
