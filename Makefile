CC	= gcc
CFLAGS	= -Wall -Wextra -g -std=c99 -O2 \
	  -Wp,-D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4 -fstack-protector \
	  -fexceptions -fPIE
LDFLAGS	= -Wl,-z,relro,-z,now,-z,defs,--as-needed -pie

lemem: lemem.c
	 $(CC) $(CFLAGS) $(LDFLAGS) -o lemem lemem.c

clean:
	rm -f lemem
