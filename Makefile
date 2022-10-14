CC := gcc
LDFLAGS := -lssl -lcrypto -lsqlite3
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: homeserver

homeserver: homeserver.o
	$(CC) $(CFLAGS) -o homeserver homeserver.o $(LDFLAGS)

homeserver.o: homeserver.c
	$(CC) $(CFLAGS) -c homeserver.c

clean:
	rm -f homeserver homeserver.o
