CC := gcc
LDFLAGS := -lssl -lcrypto
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: ssl-client homeserver

ssl-client: ssl-client.o
	$(CC) $(CFLAGS) -o ssl-client ssl-client.o $(LDFLAGS)

ssl-client.o: ssl-client.c
	$(CC) $(CFLAGS) -c ssl-client.c

homeserver: homeserver.o
	$(CC) $(CFLAGS) -o homeserver homeserver.o $(LDFLAGS)

homeserver.o: homeserver.c
	$(CC) $(CFLAGS) -c homeserver.c

clean:
	rm -f homeserver homeserver.o ssl-client ssl-client.o
