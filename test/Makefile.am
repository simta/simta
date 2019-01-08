AM_LDFLAGS = \
        @DENSER_LIBS@ \
        @JEMALLOC_LIBS@ \
        @LIBIDN2_LIBS@ \
        @LIBSASL_LIBS@ \
        @LIBSSL_LIBS@ \
        @LIBUCL_LIBS@ \
        @OPENARC_LIBS@ \
        @OPENDKIM_LIBS@ \
        @SNET_LIBS@ \
        @EXTRALIBS@ \
        @CMOCKA_LIBS@

AM_CPPFLAGS = \
        @DENSER_CFLAGS@ \
        @JEMALLOC_CFLAGS@ \
        @LDAP_CPPFLAGS@ \
        @LIBIDN2_CFLAGS@ \
        @LIBSASL_CFLAGS@ \
        @LIBSSL_CFLAGS@ \
        @LIBUCL_CFLAGS@ \
        @LIBWRAP_CPPFLAGS@ \
        @OPENARC_CFLAGS@ \
        @OPENDKIM_CFLAGS@ \
        @SNET_CFLAGS@ \
        @CMOCKA_CFLAGS@ \
        -I$(top_srcdir)

COMMON_FILES = \
        ../address.c \
        ../argcargv.c ../argcargv.h \
        ../bounce.c \
        ../dns.c ../dns.h \
        ../embedded_config.h ../embedded_schema.h \
        ../envelope.c ../envelope.h \
        ../expand.c ../expand.h \
        ../header.c ../header.h \
        ../line_file.c ../line_file.h \
        ../ll.c ../ll.h \
        ../ml.c ../ml.h \
        ../q_cleanup.c \
        ../queue.c ../queue.h \
        ../red.c ../red.h \
        ../simta.c ../simta.h \
        ../simta_sasl.c ../simta_sasl.h \
        ../simta_statsd.c ../simta_statsd.h \
        ../simta_ucl.c ../simta_ucl.h \
        ../smtp.c ../smtp.h \
        ../srs.c ../srs.h \
        ../spf.c ../spf.h \
        ../wildcard.c ../wildcard.h \
        ../yasl.c ../yasl.h

if BUILD_LDAP
COMMON_FILES += ../dn.c ../dn.h ../simta_ldap.c ../simta_ldap.h
endif

if BUILD_LMDB
COMMON_FILES += ../simta_lmdb.c ../simta_lmdb.h
endif

if BUILD_SSL
COMMON_FILES += ../md.c ../md.h ../tls.c ../tls.h
endif

EXTRA_DIST = public_suffix_list.dat pytest.ini conftest.py test_simta_modes.py int_config conf

if BUILD_CMOCKA
check_PROGRAMS = cmocka_dmarc cmocka_header cmocka_md
cmocka_dmarc_SOURCES = unit_dmarc.c ../dmarc.c ../dmarc.h $(COMMON_FILES)
cmocka_header_SOURCES = unit_header.c $(COMMON_FILES)
cmocka_md_SOURCES = unit_md.c $(COMMON_FILES)
endif

check:
	pytest -x --verbose
