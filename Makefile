#CFLAGS:=-O0 -g3 -std=c99
CFLAGS:=-std=c99
LDLIBS:=-lexpat

gangite: gangite.c

clean:
	rm -rf gangite
