CC=gcc
CFLAGS=-Wall -g -std=c99 -O2
LDFLAGS=

lemem: lemem.c
	 $(CC) $(CFLAGS) -o lemem lemem.c

clean:
	rm -f lemem
