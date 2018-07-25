CC = gcc
LDLIBS = -lcrypto
CFLAGS = -g -Wall

PROG = main
OBJS = edwards25519.o ed25519.o cosi.o


all: $(PROG)

main: $(OBJS) main.o

main.o : main.c

cosi.o : cosi.c

ed25519.o : ed25519.c

edwards25519.o : edwards25519.c

clean:
	rm -f $(OBJS) $(PROG) check.o bench.o

again: clean
	make
