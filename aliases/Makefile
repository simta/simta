# Makefile.  Generated from Makefile.in by configure.

SRC= 		make_db.c argcargv.c bdb.c
OBJ= 		make_db.o argcargv.o ../bdb.o

CC=		gcc
OPTOPTS=	-Wall -Wmissing-prototypes -Wconversion
INSTALL=	/usr/bin/install -c
INCPATH=	-I/usr/include
DEFS=		
LIBPATH=	-L/usr/local/BerkeleyDB.4.1/lib
LIBS=		-ldb
TAGSFILE=	

CFLAGS=		${DEFS} ${OPTOPTS} ${INCPATH}

TARGETS=	make_db

all : ${TARGETS}

make_db : ${OBJ} Makefile
	${CC} ${CFLAGS} ${LDFLAGS} -o make_db ${OBJ} ${LIBPATH} ${LIBS}

FRC :

clean :
	rm -f a.out core* *.o *.bak *[Ee]rrs tags
	rm -f ${TARGETS}
	rm -f simlog

realclean : clean
	rm -rf autom4te.cache
	rm -f config.status config.log
	rm -f Makefile
	cd libsnet; ${MAKE} ${MFLAGS} distclean

# DO NOT DELETE THIS LINE
