SRCS=		main.c pcaputil.c
PROG=		matrixdump
CFLAGS+=	-I/usr/local/include -g
LDFLAGS+=	-L/usr/local/lib -g
LDADD=		-lcurses -lpcap -ldnet
NOMAN=		Yes

.include <bsd.prog.mk>
