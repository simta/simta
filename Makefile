################## Some of this may need to be edited ##################

DESTDIR=/usr/local
MANDIR=${DESTDIR}/man
BINDIR=${DESTDIR}/bin
ETCDIR=${DESTDIR}/etc
SBINDIR=${DESTDIR}/sbin

SIMTALOG=LOG_MAIL

# Stock compiler:
CC=	cc

# For gcc:
#CC=	gcc
# These options might work on your system:
OPTOPTS=-Wall -Wstrict-prototypes -Wmissing-prototypes -Wconversion

# For most platforms:
INSTALL=	install

# For Solaris:
#INSTALL=	/usr/ucb/install
#ADDLIBS=	

################ Nothing below should need editing ###################

SRC=    daemon.c receive.c argcargv.c envelope.c auth.c base64.c \
	simsend.c rfc822.c rcptlist.c tz.c tlsconnect.c
SIMTAOBJ=	daemon.o receive.o argcargv.o envelope.o base64.o tz.o
TLSCONOBJ=	tlsconnect.o

INCPATH=	-Ilibsnet
DEFS=	-DLOG_SIMTA=${SIMTALOG} -DTLS
CFLAGS=	${DEFS} ${OPTOPTS} ${INCPATH}
TAGSFILE=	tags
LIBPATH=	-Llibsnet
LIBS=	${ADDLIBS} -lsnet -lssl -lcrypto

TARGETS=	simta

all : ${TARGETS}

daemon.o : daemon.c
	${CC} ${CFLAGS} -DVERSION=\"`cat VERSION`\" -c daemon.c

simta : libsnet/libsnet.a ${SIMTAOBJ} Makefile
	${CC} ${CFLAGS} ${LDFLAGS} -o simta ${SIMTAOBJ} ${LIBPATH} ${LIBS}

tlsconnect : libsnet/libsnet.a ${TLSCONOBJ} Makefile
	${CC} ${CFLAGS} ${LDFLAGS} -o tlsconnect ${TLSCONOBJ} ${LIBPATH} ${LIBS}

simsendmail : ${SIMSENDMAILOBJ}
	${CC} ${CFLAGS} ${LDFALGS} -o simsendmail ${SIMSENDMAILOBJ} \
		${LIBPATH} ${LIBS}

FRC :

libsnet/libsnet.a : FRC
	cd libsnet; ${MAKE} ${MFLAGS} CC=${CC} DEFS="${DEFS}"

VERSION=`date +%Y%m%d`
DISTDIR=../simta-${VERSION}

dist : clean
	mkdir ${DISTDIR}
	tar chfFFX - EXCLUDE . | ( cd ${DISTDIR}; tar xvf - )
	chmod +w ${DISTDIR}/Makefile
	echo ${VERSION} > ${DISTDIR}/VERSION

clean :
	cd libsnet; ${MAKE} ${MFLAGS} clean
	rm -f a.out core* *.o *.bak *[Ee]rrs tags
	rm -f ${TARGETS}

tags : ${SRC}
	cwd=`pwd`; \
	for i in ${SRC}; do \
	    ctags -t -a -f ${TAGSFILE} $$cwd/$$i; \
	done

depend :
	for i in ${SRC} ; do \
	    ${CC} -M ${DEFS} ${INCPATH} $$i | \
	    awk ' { if ($$1 != prev) { print rec; rec = $$0; prev = $$1; } \
		else { if (length(rec $$2) > 78) { print rec; rec = $$0; } \
		else rec = rec " " $$2 } } \
		END { print rec } ' >> makedep; done
	sed -n '1,/^# DO NOT DELETE THIS LINE/p' Makefile > Makefile.tmp
	cat makedep >> Makefile.tmp
	rm makedep
	echo '# DEPENDENCIES MUST END AT END OF FILE' >> Makefile.tmp
	echo '# IF YOU PUT STUFF HERE IT WILL GO AWAY' >> Makefile.tmp
	echo '# see make depend above' >> Makefile.tmp
	rm -f Makefile.bak
	cp Makefile Makefile.bak
	mv Makefile.tmp Makefile

# DO NOT DELETE THIS LINE
