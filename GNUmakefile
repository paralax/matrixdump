# $Id$

all: matrixdump

matrixdump: main.c pcaputil.c
	gcc ${CFLAGS} -c -I/usr/local/include main.c
	gcc ${CFLAGS} -c -I/usr/local/include pcaputil.c
	gcc -o matrixdump -L/usr/local/lib main.o pcaputil.o -lpcap -lcurses -ldnet

clean:
	rm -f *.core matrixdump *.o
