# mimimal Makefile

all: fsm

CFLAGS = -g 

fsm: fsm.c util.o queue.o
util.o: util.h
queue.o: queue.h

.o : .c

clean: 
	rm -f fsm *.o
