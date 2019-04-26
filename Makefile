CC=gcc
CFLAGS=-Wall -Wextra -g -std=c99 -O2
LDFLAGS=

lemem: lemem.c
	 $(CC) $(CFLAGS) -o lemem lemem.c

clean:
	rm -f lemem
