CC = gcc
LDLIBS = -lcrypto
CFLAGS = -g -O3 -Wall
PROG = bench
OBJS = edwards25519.o ed25519.o cosi.o my_random.o

all: $(PROG)

bench: $(OBJS) bench.o

cosi.o : cosi.c

ed25519.o : ed25519.c

edwards25519.o : edwards25519.c

bench.o: bench.c

my_random.o: my_random.c

clean:
	rm -f $(OBJS) $(PROG) bench.o

again: clean
	make
