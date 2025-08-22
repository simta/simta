ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . test

COMMON_LIBS = \
	@DENSER_LIBS@ \
	@JEMALLOC_LIBS@ \
	@LIBIDN2_LIBS@ \
	@LIBSASL_LIBS@ \
	@LIBSSL_LIBS@ \
	@LIBUCL_LIBS@ \
	@MIMALLOC_LIBS@ \
	@OPENARC_LIBS@ \
	@OPENDKIM_LIBS@ \
	@EXTRALIBS@

AM_CPPFLAGS = \
	@CMOCKA_CFLAGS@ \
	@DENSER_CFLAGS@ \
	@JEMALLOC_CFLAGS@ \
	@LDAP_CPPFLAGS@ \
	@LIBIDN2_CFLAGS@ \
	@LIBSASL_CFLAGS@ \
	@LIBSSL_CFLAGS@ \
	@LIBUCL_CFLAGS@ \
	@LIBWRAP_CPPFLAGS@ \
	@MIMALLOC_CFLAGS@ \
	@OPENARC_CFLAGS@ \
	@OPENDKIM_CFLAGS@

bin_PROGRAMS = \
	simalias \
	simconnect \
	simdmarc \
	simexpander \
	simorgdomain \
	simrbl \
	simreverse \
	simspf \
	simsrs

sbin_PROGRAMS = \
	simc \
	simsendmail \
	simta

noinst_PROGRAMS = \
	genimbed \
	snetcat

pkglibexec_PROGRAMS = simda

COMMON_FILES = \
	address.c \
	argcargv.c argcargv.h \
	bounce.c \
	dns.c dns.h \
	embedded_config.h embedded_schema.h \
	envelope.c envelope.h \
	expand.c expand.h \
	header.c header.h \
	line_file.c line_file.h \
	ll.c ll.h \
	ml.c ml.h \
	queue.c queue.h \
	red.c red.h \
	simta.c simta.h \
	simta_malloc.c simta_malloc.h \
	simta_snet.c simta_snet.h \
	simta_statsd.c simta_statsd.h \
	simta_ucl.c simta_ucl.h \
	simta_util.c simta_util.h \
	smtp.c smtp.h \
	srs.c srs.h \
	spf.c spf.h \
	yasl.c yasl.h

if BUILD_LDAP
COMMON_FILES += dn.c dn.h simta_ldap.c simta_ldap.h
endif

if BUILD_LMDB
COMMON_FILES += simta_lmdb.c simta_lmdb.h
endif

if BUILD_SASL
COMMON_FILES += simta_sasl.c simta_sasl.h
endif

if BUILD_SSL
COMMON_FILES += md.c md.h tls.c tls.h
noinst_PROGRAMS += simck
simck_SOURCES = simck.c $(COMMON_FILES)
simck_LDADD = $(COMMON_LIBS)
endif

if BUILD_CMOCKA
check_PROGRAMS = \
	test/cmocka_dmarc \
	test/cmocka_header \
	test/cmocka_ldap \
	test/cmocka_md \
	test/cmocka_simta_util \
	test/cmocka_yasl

test_cmocka_dmarc_LDADD = $(COMMON_LIBS) @CMOCKA_LIBS@
test_cmocka_dmarc_SOURCES = test/unit_dmarc.c dmarc.c dmarc.h $(COMMON_FILES)
test_cmocka_header_LDADD = $(COMMON_LIBS) @CMOCKA_LIBS@
test_cmocka_header_SOURCES = test/unit_header.c $(COMMON_FILES)
test_cmocka_ldap_LDADD = $(COMMON_LIBS) @CMOCKA_LIBS@
test_cmocka_ldap_LDFLAGS = -Wl,--wrap=ldap_count_entries -Wl,--wrap=ldap_initialize -Wl,--wrap=ldap_is_ldap_url -Wl,--wrap=ldap_msgfree -Wl,--wrap=ldap_sasl_bind_s -Wl,--wrap=ldap_search_ext_s -Wl,--wrap=ldap_set_option -Wl,--wrap=ldap_unbind_ext -Wl,--wrap=ldap_url_parse
test_cmocka_ldap_SOURCES = test/unit_ldap.c $(COMMON_FILES)
test_cmocka_md_LDADD = $(COMMON_LIBS) @CMOCKA_LIBS@
test_cmocka_md_SOURCES = test/unit_md.c $(COMMON_FILES)
test_cmocka_simta_util_LDADD = $(COMMON_LIBS) @CMOCKA_LIBS@
test_cmocka_simta_util_SOURCES = test/unit_simta_util.c $(COMMON_FILES)
test_cmocka_yasl_LDADD = $(COMMON_LIBS) @CMOCKA_LIBS@
test_cmocka_yasl_SOURCES = test/unit_yasl.c $(COMMON_FILES)
endif

BUILT_SOURCES = embedded_config.h embedded_schema.h

genimbed_SOURCES = genimbed.c
genimbed_LDADD = $(COMMON_LIBS)
simalias_SOURCES = simalias.c $(COMMON_FILES)
simalias_LDADD = $(COMMON_LIBS)
simc_SOURCES = simc.c $(COMMON_FILES)
simc_LDADD = $(COMMON_LIBS)
simconnect_SOURCES = simconnect.c $(COMMON_FILES)
simconnect_LDADD = $(COMMON_LIBS)
simda_SOURCES = simda.c
simda_LDADD = $(COMMON_LIBS)
simdmarc_SOURCES = simdmarc.c dmarc.c dmarc.h $(COMMON_FILES)
simdmarc_LDADD = $(COMMON_LIBS)
simexpander_SOURCES = simexpander.c $(COMMON_FILES)
simexpander_LDADD = $(COMMON_LIBS)
simorgdomain_SOURCES = simorgdomain.c dmarc.c dmarc.h $(COMMON_FILES)
simorgdomain_LDADD = $(COMMON_LIBS)
simrbl_SOURCES = simrbl.c simta_acl.c simta_acl.h $(COMMON_FILES)
simrbl_LDADD = $(COMMON_LIBS)
simreverse_SOURCES = simreverse.c $(COMMON_FILES)
simreverse_LDADD = $(COMMON_LIBS)
simsendmail_SOURCES = simsendmail.c $(COMMON_FILES)
simsendmail_LDADD = $(COMMON_LIBS)
simspf_SOURCES = simspf.c $(COMMON_FILES)
simspf_LDADD = $(COMMON_LIBS)
simsrs_SOURCES = simsrs.c $(COMMON_FILES)
simsrs_LDADD = $(COMMON_LIBS)
simta_SOURCES = daemon.c dmarc.c dmarc.h q_cleanup.c q_cleanup.h receive.c simta_acl.c simta_acl.h $(COMMON_FILES)
simta_LDADD = $(COMMON_LIBS)
snetcat_SOURCES = snetcat.c $(COMMON_FILES)
snetcat_LDADD = $(COMMON_LIBS)

dist_man_MANS = simsendmail.1 simc.8 simta.8

EXTRA_DIST = \
	COPYING.yasl \
	VERSION \
	packaging/rpm/simta.service \
	packaging/rpm/simta.spec \
	simta.conf \
	simta.conf.schema

embedded_config.h: genimbed$(EXEEXT) simta.conf Makefile
	./genimbed$(EXEEXT) simta.conf CONFIG_BASE > embedded_config.h

embedded_schema.h: genimbed$(EXEEXT) simta.conf.schema Makefile
	./genimbed$(EXEEXT) simta.conf.schema CONFIG_SCHEMA > embedded_schema.h

install-data-local:
	${INSTALL} -m 0750 -d \
		$(DESTDIR)$(localstatedir)/spool/simta \
		$(DESTDIR)$(localstatedir)/spool/simta/command \
		$(DESTDIR)$(localstatedir)/spool/simta/dead \
		$(DESTDIR)$(localstatedir)/spool/simta/etc \
		$(DESTDIR)$(localstatedir)/spool/simta/fast \
		$(DESTDIR)$(localstatedir)/spool/simta/local \
		$(DESTDIR)$(localstatedir)/spool/simta/slow

install-exec-hook:
	ln -f $(DESTDIR)$(sbindir)/simsendmail$(EXEEXT) $(DESTDIR)$(sbindir)/sendmail$(EXEEXT)
if CHOWN_FILES
	chown simta:simta $(DESTDIR)$(sbindir)/simc$(EXEEXT)
	chown simta:simta $(DESTDIR)$(sbindir)/simsendmail$(EXEEXT)
	chown -R simta:simta $(DESTDIR)$(localstatedir)/spool/simta
endif
	chmod u+s $(DESTDIR)$(sbindir)/simc$(EXEEXT)
	chmod u+s $(DESTDIR)$(sbindir)/simsendmail$(EXEEXT)

rpm: dist-xz
	rpmbuild -ta $(distdir).tar.xz
